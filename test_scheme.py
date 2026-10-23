import time
import json
from registry.provers import PROVER_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from registry.trees import TREE_REGISTRY
from registry.setup import SETUP_REGISTRY
import csv
from datetime import datetime

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

def generate_tree(method, width, hash_fn=None, setup=None):
    tree_class = TREE_REGISTRY[method]
    tree = tree_class(width, db_path="", hash_fn=hash_fn, setup_object=setup)
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
    global_setup = json.load(open("global_setup.json"))
    
    WIDTH = global_setup["WIDTH"]
    KEY_LENGTH = global_setup["KEY_LENGTH"]
    VALUE_LENGTH = global_setup["VALUE_LENGTH"]
    SECRET = global_setup["SECRET"]
    TREE_TYPE = global_setup["TREE_TYPE"]
    PROVER_TYPE = global_setup["PROVER_TYPE"]
    VERIFIER_TYPE = global_setup["VERIFIER_TYPE"]
    SETUP_TYPE = global_setup["SETUP_TYPE"]
    KEYS_TO_PROVE = global_setup["KEYS_TO_PROVE"]
    HASH_FN = global_setup["HASH_FN"]

    setup_object = generate_setup(SETUP_TYPE, SECRET, WIDTH)
    print("Generated setup")

    data = {}
    with open("data.json") as f:
        data = json.load(f)

    print("Loaded random test data")

    data_tree = generate_tree(TREE_TYPE, WIDTH, hash_fn=HASH_FN, setup=setup_object)

    print("Generated data tree")

    for idx, (k, v) in enumerate(data.items()):
        if idx % 1000 == 0:
            print(f" Inserting key of index: {idx}")
        # convert key string -> bytes 
        key_bytes = hex_to_bytes(k, KEY_LENGTH)

        val_bytes = hex_to_bytes(v, VALUE_LENGTH)
        #v = bytes_to_int(val_bytes)

        # insert into tree
        #print("Inserting key:", k, "value:", int(v, 16))
        data_tree.insert(key_bytes, val_bytes)
    print("Inserted data into tree")

    # key_bytes = [hex_to_bytes(k, KEY_LENGTH) for k in KEYS_TO_PROVE]
    # # paths_to_prove = [data_tree._key_to_path(k) for k in key_bytes]  
    # # paths_to_prove = None 
    # a = time.time()


    # # proof = generate_proof(PROVER_TYPE, data_tree, key_bytes, setup_object)
    # # print('Generated proof:', proof)
    # # print(proof.keys())
    # # with open('proof', 'wb') as f:
    # #     pickle.dump(proof, f)

    # # -------------------------snark boundary-------------------------

    # proof, proof_size = generate_proof(PROVER_TYPE, data_tree, key_bytes, setup_object)
    # commitments, w = proof
    # proving_time = time.time() - a
    # print("Generated proof in %.3f seconds" % (proving_time))
    # print('-------------------')

    # print("Proof size:")
    # print(proof_size, "bytes")


    # print("Printing root")
    # print(data_tree.root.value)
    
    # a = time.time()

    # root_data = get_root_data(TREE_TYPE, data_tree.root)
    
    # assert verify_proof(VERIFIER_TYPE, (commitments, w), root_data, key_bytes, [hex_to_bytes(data[k], VALUE_LENGTH) for k in KEYS_TO_PROVE], setup_object)

    # verification_time = time.time() - a
    # print("Verified proof in %.3f seconds" % (verification_time))
    # # Save to CSV
    # csv_file = 'results.csv'
    # fieldnames = ['datetime', 'WIDTH', 'KEY_LENGTH', 'VALUE_LENGTH', 'SECRET', 'TREE_TYPE', 'PROVER_TYPE', 'VERIFIER_TYPE', 'SETUP_TYPE', 'num_of_KEYS_TO_PROVE', 'proof_size', 'proving_time', 'verification_time']
    # row = {
    #     'datetime': datetime.now().isoformat(),
    #     'WIDTH': WIDTH,
    #     'KEY_LENGTH': KEY_LENGTH,
    #     'VALUE_LENGTH': VALUE_LENGTH,
    #     'SECRET': SECRET,
    #     'TREE_TYPE': TREE_TYPE,
    #     'PROVER_TYPE': PROVER_TYPE,
    #     'VERIFIER_TYPE': VERIFIER_TYPE,
    #     'SETUP_TYPE': SETUP_TYPE,
    #     'num_of_KEYS_TO_PROVE': len(KEYS_TO_PROVE),
    #     'proof_size': proof_size,
    #     'proving_time': proving_time,
    #     'verification_time': verification_time
    # }
    
    # with open(csv_file, 'a', newline='') as f:
    #     writer = csv.DictWriter(f, fieldnames=fieldnames)
    #     if f.tell() == 0:  # Write header if file is empty
    #         writer.writeheader()
    #     writer.writerow(row)

if __name__ == '__main__':
    test()