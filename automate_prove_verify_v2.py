"""
Run prove_verify.py over many trees and many prover/verifier pairs per tree,
without depending on proving_setup.json.

Tree parameters (TREE_TYPE, HASH_FN, SETUP_TYPE, WIDTH, SECRET) are read from
tree_storage/<id>/tree_info.json and can be overridden per tree in the input
JSON. The generated setup is handed to prove_verify.py in memory, so
proving_setup.json is never read or written.

Usage:
    python3 automate_prove_verify_v2.py [input.json] [--keep-going]

Input format (default: automate_prove_verify_v2_input.json):
[
    {
        "id": "<tree id>",
        "num_keys": [1, 2, 4],
        "prover_verifier": [
            {"prover": "merkle", "verifier": "merkle"},
            {"prover": "zkstarkmerkle", "verifier": "zkstarkmerkle", "num_keys": [1, 2]}
        ],

        // optional overrides (defaults come from tree_info.json)
        "width": 8, "tree_type": "merkle", "hash_fn": "keccak",
        "setup_type": "", "secret": 123
    }
]
A pair's own "num_keys" (optional) replaces the tree-level "num_keys" for that pair.
"""
import json
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = "automate_prove_verify_v2_input.json"

# Runs prove_verify.test() with "proving_setup.json" redirected to the setup
# passed through the PV_SETUP_JSON environment variable.
RUNNER = """
import builtins, io, os
import prove_verify

_setup = os.environ["PV_SETUP_JSON"]

def _open(path, *args, **kwargs):
    if path == "proving_setup.json":
        return io.StringIO(_setup)
    return builtins.open(path, *args, **kwargs)

prove_verify.open = _open
prove_verify.test()
"""

OVERRIDES = {
    "width": "WIDTH",
    "tree_type": "TREE_TYPE",
    "hash_fn": "HASH_FN",
    "setup_type": "SETUP_TYPE",
    "secret": "SECRET",
}


def load_tree_info(tree_id):
    path = os.path.join(SCRIPT_DIR, "tree_storage", tree_id, "tree_info.json")
    with open(path) as f:
        return json.load(f)


def build_base_setup(obj):
    info = load_tree_info(obj["id"])
    setup = {
        "TREE_TYPE": info.get("TREE_TYPE", ""),
        "HASH_FN": info.get("HASH_FN", ""),
        "TREE_ID": obj["id"],
        "SETUP_TYPE": info.get("SETUP_TYPE", ""),
        "WIDTH": info.get("WIDTH"),
        "SECRET": info.get("SECRET"),
    }
    for key, setup_key in OVERRIDES.items():
        if key in obj:
            setup[setup_key] = obj[key]
    return setup


def run(setup):
    env = os.environ.copy()
    env["PV_SETUP_JSON"] = json.dumps(setup)
    return subprocess.run([sys.executable, "-c", RUNNER], cwd=SCRIPT_DIR, env=env)


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    keep_going = "--keep-going" in sys.argv[1:]
    input_path = args[0] if args else os.path.join(SCRIPT_DIR, DEFAULT_INPUT)

    with open(input_path) as f:
        objects = json.load(f)

    failures = []
    for obj in objects:
        base = build_base_setup(obj)

        for pair in obj["prover_verifier"]:
            num_keys_list = pair.get("num_keys", obj.get("num_keys"))
            if not num_keys_list:
                raise ValueError(f"No num_keys given for tree {obj['id']} / pair {pair}")

            for num_keys in num_keys_list:
                setup = dict(base)
                setup["PROVER_TYPE"] = pair["prover"]
                setup["VERIFIER_TYPE"] = pair["verifier"]
                setup["NUM_KEYS_TO_PROVE"] = num_keys

                label = (f"tree={setup['TREE_ID']} width={setup['WIDTH']} "
                         f"prover={setup['PROVER_TYPE']} verifier={setup['VERIFIER_TYPE']} "
                         f"num_keys={num_keys}")
                print(f"\n=== {label} ===", flush=True)

                result = run(setup)
                if result.returncode != 0:
                    if not keep_going:
                        sys.exit(f"FAILED: {label}")
                    failures.append(label)

    if failures:
        print("\nFailed runs:")
        for label in failures:
            print(f"  {label}")
        sys.exit(1)


if __name__ == "__main__":
    main()
