import time
import json
from registry.provers import PROVER_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from registry.trees import TREE_REGISTRY
from registry.setup import SETUP_REGISTRY
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

def generate_tree(method, width, tree_id, hash_fn=None, setup=None):
    tree_class = TREE_REGISTRY[method]
    db_path = f'./tree_storage/{tree_id}'
    tree = tree_class(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup)
    return tree

def generate_setup(method, secret, width=None):
    if not method:
        return None
    setup_class = SETUP_REGISTRY[method]
    setup = setup_class(secret, width)
    return setup

def get_root_data(method, root):
    if method in ('verkle', 'verkle_eip6800'):
        return root.commitment_to_children
    return root.value

def hex_to_bytes(s):
    s = s[2:] if s.startswith("0x") else s
    b = bytes.fromhex(s)
    return b

def bytes_to_int(b):
    return int.from_bytes(b, byteorder='big')

def test():
    global_setup = json.load(open("proving_setup.json"))
    
    WIDTH = global_setup["WIDTH"]
    SECRET = global_setup["SECRET"]
    TREE_TYPE = global_setup["TREE_TYPE"]
    PROVER_TYPE = global_setup["PROVER_TYPE"]
    VERIFIER_TYPE = global_setup["VERIFIER_TYPE"]
    SETUP_TYPE = global_setup["SETUP_TYPE"]
    NUM_KEYS_TO_PROVE = global_setup["NUM_KEYS_TO_PROVE"]
    HASH_FN = global_setup["HASH_FN"]
    TREE_ID = global_setup["TREE_ID"]

    setup_object = generate_setup(SETUP_TYPE, SECRET, WIDTH)
    print("Generated setup")

    db_path = f'./tree_storage/{TREE_ID}'
    # data_path = f'{db_path}/data.json'
    tree_info_path = f'{db_path}/tree_info.json'

    tree_info = json.load(open(tree_info_path))
    NUM_KEYS_TREE = tree_info["NUM_KEYS"]

    if NUM_KEYS_TO_PROVE > NUM_KEYS_TREE:
        raise ValueError(f"NUM_KEYS_TO_PROVE ({NUM_KEYS_TO_PROVE}) cannot be greater than the number of keys in the tree ({NUM_KEYS_TREE}).")

    data = {}
    # with open(data_path) as f:
    #     data = json.load(f)


    # if TREE_TYPE == "verkle":
    #     data_path = f"{db_path}/data.json"
    #     with open(data_path) as f:
    #         data = json.load(f)
    # else:
    # data_file_path = "random_data.json" if TREE_TYPE == "verkle" else "data.json"
    if TREE_TYPE == "verkle_eip6800":
        # Leaf keys/values written by generate_tree.py (2 leaves per account)
        with open(f"{db_path}/data.json") as f:
            data = json.load(f)
    else:
        data_file_path = "data.json"
        with open(data_file_path) as f:
            data = json.load(f)

        data = dict(list(data.items())[:NUM_KEYS_TREE])

    print("Loaded tree data")

    data_tree = generate_tree(TREE_TYPE, WIDTH, TREE_ID, hash_fn=HASH_FN, setup=setup_object)

    print("Generated data tree")

    # Randomly select keys to prove
    all_keys = list(data.keys())
    shuffled_keys = all_keys.copy()
    random.shuffle(shuffled_keys)
    keys_to_prove = shuffled_keys[:NUM_KEYS_TO_PROVE]
    key_bytes = [hex_to_bytes(k) for k in keys_to_prove]

    a = time.time()


    # proof = generate_proof(PROVER_TYPE, data_tree, key_bytes, setup_object)
    # print('Generated proof:', proof)
    # print(proof.keys())
    # with open('proof', 'wb') as f:
    #     pickle.dump(proof, f)

    # -------------------------snark boundary-------------------------

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
        'NUM_KEYS_TREE': NUM_KEYS_TREE,
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