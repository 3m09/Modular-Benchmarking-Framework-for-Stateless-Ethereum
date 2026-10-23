import json
import time
from registry.trees import TREE_REGISTRY
from registry.setup import SETUP_REGISTRY
from registry.provers import PROVER_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from datetime import datetime
from pathlib import Path
import uuid
from get_eth_data import fetch_trie_kv_pairs
from datetime import datetime
import csv
from datetime import datetime
import random

def generate_proof(method, tree, keys, setup=None):
    prover_class = PROVER_REGISTRY[method]
    prover = prover_class(setup)
    proof = prover.generate_proof(tree, keys)
    proof_size = prover.proof_size(*proof)
    return proof, proof_size

def verify_proof(method, proof, root, keys, values, setup=None):
    verifier_class = VERIFIER_REGISTRY[method]
    verifier = verifier_class(setup)
    return verifier.verify_proof(values, keys, root, proof)

def generate_tree(method, width, db_path, hash_fn=None, setup=None):
    tree_class = TREE_REGISTRY[method]
    tree = tree_class(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup)
    return tree

def generate_setup(method, secret, width=None):
    if not method:
        return None
    setup_class = SETUP_REGISTRY[method]
    setup = setup_class(secret, width)
    return setup

def get_root_data(method, root):
    if method == 'verkle':
        return root.commitment_to_children
    return root.value

def hex_to_bytes(s, expected_length=32):
    s = s[2:] if s.startswith("0x") else s
    b = bytes.fromhex(s)
    if len(b) < expected_length:
        b = b'\x00' * (expected_length - len(b)) + b
    return b

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def test():
    experiment_setup = json.load(open("experiment.json"))

    for num_keys in experiment_setup["num_key_tree"]:
        for width in experiment_setup["width"]:
            # global_setup = json.load(open("tree_generation_setup.json"))
            
            WIDTH = width
            KEY_LENGTH = 32
            SECRET = 1927409816240961209460912649124
            TREE_TYPE = experiment_setup["tree_type"]
            SETUP_TYPE = "verkle_kzg" if TREE_TYPE == "verkle" else ""
            HASH_FN = experiment_setup["hash_fn"]
            NUM_KEYS = num_keys

            setup_object = generate_setup(SETUP_TYPE, SECRET, WIDTH)
            print("Generated setup")

            tree_id = str(uuid.uuid4())
            storage_root = Path("tree_storage")
            storage_root.mkdir(parents=True, exist_ok=True)

            db_path = str(storage_root / tree_id)
            # tree_data_path = f"{db_path}/data.json"

            Path(db_path).mkdir(parents=True, exist_ok=True)
        
            info_path = Path(db_path) / "tree_info.json"
            with open(info_path, "w") as f:
                json.dump({
                    "TREE_TYPE": TREE_TYPE,
                    "HASH_FN": HASH_FN,
                    "SETUP_TYPE": SETUP_TYPE,
                    "KEY_LENGTH": KEY_LENGTH,
                    "WIDTH": WIDTH,
                    "SECRET": SECRET,
                    "NUM_KEYS": NUM_KEYS
                }, f, indent=4)

            # append tree id to tree_ids.txt
            ids_path = "tree_ids.txt"
            with open(ids_path, "a") as f:
                f.write(tree_id + "\n")

            # data = fetch_trie_kv_pairs(NUM_KEYS, output_file=tree_data_path)
            data_file_path = "random_data.json" if TREE_TYPE == "verkle" else "data.json"
            with open(data_file_path) as f:
                data = json.load(f)
            
            data = dict(list(data.items())[:NUM_KEYS])

            print("Loaded real Ethereum data")

            data_tree = generate_tree(TREE_TYPE, WIDTH, db_path=db_path, hash_fn=HASH_FN, setup=setup_object)

            print("Generated data tree")

            for idx, (k, v) in enumerate(data.items()):
                if idx % 100 == 0:
                    print(f" Inserting key of index: {idx}")
                    
                # 1. KEY: Original 32-byte hash
                key_bytes = hex_to_bytes(k, KEY_LENGTH)  

                # 2. VALUE: Decode dynamically
                clean_hex_val = v[2:] if v.startswith('0x') else v
                val_bytes = bytes.fromhex(clean_hex_val)
                data_tree.insert(key_bytes, val_bytes)

            print("Inserted data into tree")

            for prover in experiment_setup["prover"]:
                for num_keys_prove in experiment_setup["num_key_prove"]:

                    if num_keys_prove > NUM_KEYS:
                        raise ValueError(f"NUM_KEYS_TO_PROVE ({num_keys_prove}) cannot be greater than the number of keys in the tree ({NUM_KEYS}).")
                    
                    NUM_KEYS_TO_PROVE = num_keys_prove
                    PROVER_TYPE = prover
                    VERIFIER_TYPE = prover  # Assuming we want to use the same type for verification

                    # Randomly select keys to prove
                    all_keys = list(data.keys())
                    shuffled_keys = all_keys.copy()
                    random.shuffle(shuffled_keys)
                    keys_to_prove = shuffled_keys[:NUM_KEYS_TO_PROVE]
                    key_bytes = [hex_to_bytes(k) for k in keys_to_prove]

                    a = time.time()

                    proof, proof_size = generate_proof(PROVER_TYPE, data_tree, key_bytes, setup_object)
                    commitments, w = proof
                    proving_time = time.time() - a
                    print("Generated proof in %.3f seconds" % (proving_time))
                    print('-------------------')

                    print("Proof size:")
                    print(proof_size, "bytes")


                    print("Printing root")
                    print(data_tree.root.value)
                    
                    a = time.time()

                    root_data = get_root_data(TREE_TYPE, data_tree.root)
                    
                    assert verify_proof(VERIFIER_TYPE, (commitments, w), root_data, key_bytes, [hex_to_bytes(data[k]) for k in keys_to_prove], setup_object)

                    verification_time = time.time() - a
                    print("Verified proof in %.3f seconds" % (verification_time))
                    # Save to CSV
                    csv_file = 'results_latest.csv'
                    fieldnames = ['datetime', 'WIDTH', 'TREE_TYPE', 'PROVER_TYPE', 'VERIFIER_TYPE', 'SETUP_TYPE', 'NUM_KEYS_TO_PROVE', 'NUM_KEYS_TREE', 'proof_size', 'proving_time', 'verification_time']
                    row = {
                        'datetime': datetime.now().isoformat(),
                        'WIDTH': WIDTH,
                        'TREE_TYPE': TREE_TYPE,
                        'PROVER_TYPE': PROVER_TYPE,
                        'VERIFIER_TYPE': VERIFIER_TYPE,
                        'SETUP_TYPE': SETUP_TYPE,
                        'NUM_KEYS_TO_PROVE': NUM_KEYS_TO_PROVE,
                        'NUM_KEYS_TREE': NUM_KEYS,
                        'proof_size': proof_size,
                        'proving_time': proving_time,
                        'verification_time': verification_time
                    }
                    
                    with open(csv_file, 'a', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=fieldnames)
                        if f.tell() == 0:  # Write header if file is empty
                            writer.writeheader()
                        writer.writerow(row)

if __name__ == '__main__':
    test()