"""
Benchmark runner used for the paper.

    python benchmark.py experiments/paper_config.json [--only NAME ...]

For every experiment in the config it builds (or reuses) one tree per
(tree type, hash, width, tree size) from the first `tree size` accounts of
data.json, then for every prover, batch size and repetition:

  * samples `batch` accounts with a seeded RNG; the sample depends only on
    (seed, tree size, batch, repetition), so every scheme proves the same accounts;
  * times proof generation and verification with time.perf_counter;
  * appends one row to the output CSV, including whether the proof verified.

An account is one MPT key (keccak(address) -> RLP account). For the EIP-6800
Verkle tree an account is two leaves under one stem (BASIC_DATA, CODE_HASH),
and both are proven.
"""
import argparse
import csv
import gc
import json
import os
import random
import subprocess
import time
import traceback
from datetime import datetime
from pathlib import Path

from registry.trees import TREE_REGISTRY
from registry.provers import PROVER_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from registry.setup import SETUP_REGISTRY
from verkle.eip6800 import account_to_leaves, STEM_LENGTH

DATA_FILE = "data.json"
SECRET = 1927409816240961209460912649124
FIELDS = [
    "datetime", "experiment", "tree_type", "hash_fn", "width", "num_keys_tree",
    "prover", "num_keys_prove", "num_leaves_proven", "rep", "seed",
    "proof_size", "proving_time", "verification_time", "verified", "error", "git_commit",
]


def git_commit():
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        dirty = subprocess.run(["git", "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True).stdout.strip()
        return out + ("-dirty" if dirty else "")
    except Exception:
        return "unknown"


def on_mains():
    """True unless this is a laptop running on battery (CPU frequency is capped then)."""
    supplies = Path("/sys/class/power_supply")
    mains = [d for d in supplies.glob("*") if (d / "type").exists() and (d / "type").read_text().strip() == "Mains"]
    return not mains or any((d / "online").read_text().strip() == "1" for d in mains)


def wait_for_mains():
    if not on_mains():
        print("    on battery: waiting for mains power before timing", flush=True)
        while not on_mains():
            time.sleep(30)
        time.sleep(30)


def load_accounts(n):
    with open(DATA_FILE) as f:
        items = list(json.load(f).items())
    if n > len(items):
        raise ValueError(f"data.json has only {len(items)} accounts")
    return [(bytes.fromhex(k[2:]), bytes.fromhex(v[2:])) for k, v in items[:n]]


class TreeHandle:
    """A built tree plus the statement (keys, values) to prove for a set of accounts."""

    def __init__(self, tree_type, hash_fn, width, n):
        self.tree_type, self.hash_fn, self.width, self.n = tree_type, hash_fn, width, n
        self.setup = SETUP_REGISTRY["verkle_kzg"](SECRET, width) if tree_type == "verkle_eip6800" else None
        self.accounts = load_accounts(n)
        name = f"bench-{tree_type}-{hash_fn or 'kzg'}-w{width}-n{n}"
        self.path = Path("tree_storage") / name
        info_path = self.path / "tree_info.json"
        fresh = not info_path.exists()
        self.path.mkdir(parents=True, exist_ok=True)
        self.tree = TREE_REGISTRY[tree_type](width, db_path=str(self.path), hash_fn=hash_fn, setup_object=self.setup)

        self.leaves = {}
        if tree_type == "verkle_eip6800":
            for key, value in self.accounts:
                stem, leaves = account_to_leaves(key, value)
                self.leaves[key] = [(stem + bytes([s]), v) for s, v in sorted(leaves.items())]

        if fresh:
            start = time.perf_counter()
            for i, (key, value) in enumerate(self.accounts):
                if tree_type == "verkle_eip6800":
                    stem, leaves = account_to_leaves(key, value)
                    self.tree.insert_stem(stem, leaves)
                else:
                    self.tree.insert(key, value)
            build = time.perf_counter() - start
            with open(info_path, "w") as f:
                json.dump({"TREE_TYPE": tree_type, "HASH_FN": hash_fn, "WIDTH": width, "NUM_KEYS": n,
                           "SETUP_TYPE": "verkle_kzg" if self.setup else "", "SECRET": SECRET,
                           "BUILD_SECONDS": build, "DATA_FILE": DATA_FILE}, f, indent=2)
            print(f"  built {name} in {build:.1f}s", flush=True)

    def root(self, prover):
        if self.tree_type == "verkle_eip6800":
            return self.tree.root.commitment_to_children
        return self.tree.root_hash()

    def statement(self, accounts):
        if self.tree_type == "verkle_eip6800":
            pairs = [leaf for key in accounts for leaf in self.leaves[key]]
        else:
            lookup = dict(self.accounts)
            pairs = [(key, lookup[key]) for key in accounts]
        return [k for k, _ in pairs], [v for _, v in pairs]

    def close(self):
        db = getattr(self.tree, "db", None)
        if db is not None:
            db.close()


def sample_accounts(handle, seed, batch, rep):
    rng = random.Random(f"{seed}-{handle.n}-{batch}-{rep}")
    keys = [k for k, _ in handle.accounts]
    return rng.sample(keys, batch)


def run_one(handle, prover_name, batch, rep, seed):
    accounts = sample_accounts(handle, seed, batch, rep)
    keys, values = handle.statement(accounts)
    prover = PROVER_REGISTRY[prover_name](handle.setup)
    verifier = VERIFIER_REGISTRY[prover_name](handle.setup)
    if prover_name == "zksnarkmerkle":
        from verifier.snark_merkle_verification import warm_up
        warm_up()

    gc.collect()
    start = time.perf_counter()
    proof = prover.generate_proof(handle.tree, keys)
    proving_time = time.perf_counter() - start
    proof_size = prover.proof_size(*proof)

    root = handle.root(prover_name)
    gc.collect()
    start = time.perf_counter()
    try:
        verified = bool(verifier.verify_proof(values, keys, root, proof))
    except AssertionError:
        verified = False
    verification_time = time.perf_counter() - start
    return len(keys), proof_size, proving_time, verification_time, verified


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("config")
    parser.add_argument("--only", nargs="*", help="run only these experiment names")
    parser.add_argument("--provers", nargs="*", help="run only these provers")
    args = parser.parse_args()
    config = json.load(open(args.config))
    reps, seed, output = config["reps"], config["seed"], config["output"]
    Path(output).parent.mkdir(parents=True, exist_ok=True)
    commit = git_commit()

    done = set()
    if os.path.exists(output):
        with open(output) as f:
            for row in csv.DictReader(f):
                if row["verified"] == "True":
                    done.add((row["experiment"], row["tree_type"], row["hash_fn"], row["width"],
                              row["num_keys_tree"], row["prover"], row["num_keys_prove"], row["rep"]))

    for exp in config["experiments"]:
        if args.only and exp["name"] not in args.only:
            continue
        if args.provers and not set(args.provers) & set(exp["provers"]):
            continue
        for width in exp["widths"]:
            for n in exp["tree_sizes"]:
                print(f"[{exp['name']}] {exp['tree_type']} {exp['hash_fn']} w={width} n={n}", flush=True)
                handle = TreeHandle(exp["tree_type"], exp["hash_fn"], width, n)
                try:
                    for prover_name in exp["provers"]:
                        if args.provers and prover_name not in args.provers:
                            continue
                        batches = exp.get("batch_sizes_by_prover", {}).get(prover_name, exp["batch_sizes"])
                        # Untimed warm-up first, so caches (LevelDB blocks of the upper
                        # levels, page cache, helper processes) are warm for every timed
                        # repetition alike. 16 accounts touch most upper nodes; the ZK
                        # backends only need their helper processes started.
                        warm = 1 if prover_name in ("zksnarkmerkle", "zkstarkmerkle") else min(16, n)
                        try:
                            run_one(handle, prover_name, warm, -1, seed)
                        except Exception:
                            traceback.print_exc()
                        # Repetition-major order: thermal or frequency drift during a
                        # sweep then affects every batch size alike.
                        for rep, batch in [(r, b) for r in range(reps) for b in batches if b <= n]:
                            tag = (exp["name"], exp["tree_type"], exp["hash_fn"], str(width), str(n),
                                   prover_name, str(batch), str(rep))
                            if tag in done:
                                continue
                            row = dict(zip(FIELDS[1:9], [exp["name"], exp["tree_type"], exp["hash_fn"],
                                                          width, n, prover_name, batch, ""]))
                            row.update(datetime=datetime.now().isoformat(), rep=rep, seed=seed,
                                       git_commit=commit, error="")
                            try:
                                # Timings taken on battery are throttled: wait for mains power and
                                # repeat a measurement during which the power was unplugged.
                                while True:
                                    wait_for_mains()
                                    leaves, size, tp, tv, ok = run_one(handle, prover_name, batch, rep, seed)
                                    if on_mains():
                                        break
                                    print("    power lost during measurement: repeating", flush=True)
                                row.update(num_leaves_proven=leaves, proof_size=size, proving_time=tp,
                                           verification_time=tv, verified=ok)
                            except Exception as e:
                                traceback.print_exc()
                                row.update(verified=False, error=f"{type(e).__name__}: {e}"[:300])
                            print(f"    {prover_name:17s} k={batch:<4d} rep={rep} size={row.get('proof_size')} "
                                  f"prove={row.get('proving_time', 0) or 0:.4f}s verify={row.get('verification_time', 0) or 0:.4f}s "
                                  f"ok={row['verified']}", flush=True)
                            new_file = not os.path.exists(output)
                            with open(output, "a", newline="") as f:
                                writer = csv.DictWriter(f, fieldnames=FIELDS)
                                if new_file:
                                    writer.writeheader()
                                writer.writerow(row)
                finally:
                    handle.close()


if __name__ == "__main__":
    main()
