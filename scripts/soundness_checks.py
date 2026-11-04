"""
Negative tests for every backend: an honest proof must verify, and the same
proof must be rejected when the claimed value, key or root is changed.

    python scripts/soundness_checks.py [scheme ...]      (run from the repo root)

Writes results/soundness_checks.json.
"""
import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from registry.trees import TREE_REGISTRY
from registry.provers import PROVER_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from registry.setup import SETUP_REGISTRY
from verkle.eip6800 import account_to_leaves

SECRET = 1927409816240961209460912649124
SCHEMES = {
    # name: (tree type, hash, width)
    "merkle": ("merkle", "keccak", 16),
    "merkle_w2": ("merkle", "keccak", 2),
    "merkle_optimized": ("merkle", "keccak", 16),
    "verkle_eip6800": ("verkle_eip6800", "", 16),
    "zksnarkmerkle": ("merkle", "poseidon", 16),
    "zkstarkmerkle": ("merkle", "keccak", 16),
}
N_ACCOUNTS, N_PROVE = 64, 4


def flip(b: bytes) -> bytes:
    return b[:-1] + bytes([b[-1] ^ 1])


def check(name):
    tree_type, hash_fn, width = SCHEMES[name]
    prover_name = name.replace("_w2", "")
    accounts = [(bytes.fromhex(k[2:]), bytes.fromhex(v[2:]))
                for k, v in list(json.load(open("data.json")).items())[:N_ACCOUNTS]]
    setup = SETUP_REGISTRY["verkle_kzg"](SECRET, width) if tree_type == "verkle_eip6800" else None
    tree = TREE_REGISTRY[tree_type](width, db_path=tempfile.mkdtemp(), hash_fn=hash_fn, setup_object=setup)
    pairs = []
    for key, value in accounts:
        if tree_type == "verkle_eip6800":
            stem, leaves = account_to_leaves(key, value)
            tree.insert_stem(stem, leaves)
            pairs += [(stem + bytes([s]), v) for s, v in sorted(leaves.items())]
        else:
            tree.insert(key, value)
            pairs.append((key, value))
    pairs = pairs[:N_PROVE]
    keys, values = [k for k, _ in pairs], [v for _, v in pairs]
    root = tree.root.commitment_to_children if tree_type == "verkle_eip6800" else tree.root_hash()
    other_key = next(k for k, _ in ([(stem + bytes([s]), None) for stem in [accounts[-1][0][:31]] for s in (0, 1)]
                                     if tree_type == "verkle_eip6800" else accounts[-1:]))

    prover = PROVER_REGISTRY[prover_name](setup)
    proof = prover.generate_proof(tree, keys)

    def verify(v, k, r):
        try:
            return bool(VERIFIER_REGISTRY[prover_name](setup).verify_proof(v, k, r, proof))
        except Exception:
            return False

    if tree_type == "verkle_eip6800":
        other_root = tree.root.commitment_to_children
        from py_ecc import optimized_bls12_381 as b
        other_root = b.normalize(b.add((other_root[0], other_root[1], b.FQ.one()), b.G1))
    else:
        other_root = flip(root)

    result = {
        "honest": verify(values, keys, root),
        "tampered_value_rejected": not verify([flip(values[0])] + values[1:], keys, root),
        "swapped_key_rejected": not verify(values, [other_key] + keys[1:], root),
        "tampered_root_rejected": not verify(values, keys, other_root),
    }
    db = getattr(tree, "db", None)
    if db is not None:
        db.close()
    return result


def main():
    names = sys.argv[1:] or list(SCHEMES)
    out = Path("results/soundness_checks.json")
    out.parent.mkdir(exist_ok=True)
    results = json.load(open(out)) if out.exists() else {}
    for name in names:
        try:
            results[name] = check(name)
        except Exception as e:
            results[name] = {"error": f"{type(e).__name__}: {e}"}
        print(name, results[name], flush=True)
        json.dump(results, open(out, "w"), indent=2)


if __name__ == "__main__":
    main()
