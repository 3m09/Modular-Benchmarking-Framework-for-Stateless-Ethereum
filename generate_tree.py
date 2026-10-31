import json
from registry.trees import TREE_REGISTRY
from registry.setup import SETUP_REGISTRY
from datetime import datetime
from pathlib import Path
import uuid
from get_eth_data import fetch_trie_kv_pairs
from verkle.eip6800 import account_to_leaves

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
    if method in ('verkle', 'verkle_eip6800'):
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
    global_setup = json.load(open("tree_generation_setup.json"))
    
    WIDTH = global_setup["WIDTH"]
    KEY_LENGTH = global_setup["KEY_LENGTH"]
    SECRET = global_setup["SECRET"]
    TREE_TYPE = global_setup["TREE_TYPE"]
    SETUP_TYPE = global_setup["SETUP_TYPE"]
    HASH_FN = global_setup["HASH_FN"]
    NUM_KEYS = global_setup["NUM_KEYS"]

    setup_object = generate_setup(SETUP_TYPE, SECRET, WIDTH)
    print("Generated setup")

    tree_id = str(uuid.uuid4())
    storage_root = Path("tree_storage")
    storage_root.mkdir(parents=True, exist_ok=True)

    db_path = str(storage_root / tree_id)
    # tree_data_path = f"{db_path}/data.json"

    Path(db_path).mkdir(parents=True, exist_ok=True)

    # write tree_info.json from tree_generation_setup.json
    setup_data = json.load(open("tree_generation_setup.json"))
    info_path = Path(db_path) / "tree_info.json"
    with open(info_path, "w") as f:
        json.dump(setup_data, f, indent=2)

    # append tree id to tree_ids.txt
    ids_path = "tree_ids.txt"
    with open(ids_path, "a") as f:
        f.write(tree_id + "\n")

    # data = fetch_trie_kv_pairs(NUM_KEYS, output_file=tree_data_path)
    # data_file_path = "random_data.json" if TREE_TYPE == "verkle" else "data.json"
    data_file_path = "data.json"
    with open(data_file_path) as f:
        data = json.load(f)
    
    data = dict(list(data.items())[:NUM_KEYS])

    print("Loaded real Ethereum data")

    data_tree = generate_tree(TREE_TYPE, WIDTH, db_path=db_path, hash_fn=HASH_FN, setup=setup_object)

    print("Generated data tree")

    # for idx, (k, v) in enumerate(data.items()):
    #     if idx % 100 == 0:
    #         print(f" Inserting key of index: {idx}")
    #     # convert key string -> bytes 
    #     key_bytes = hex_to_bytes(k, KEY_LENGTH)

    #     val_bytes = hex_to_bytes(v, VALUE_LENGTH)
    #     #v = bytes_to_int(val_bytes)

    #     # insert into tree
    #     #print("Inserting key:", k, "value:", int(v, 16))
    #     data_tree.insert(key_bytes, val_bytes)
    # print("Inserted data into tree")

    # for idx, (k, v) in enumerate(data.items()):
    #     if idx % 100 == 0:
    #         print(f" Inserting key of index: {idx}")
            
    #     # 1. KEY: Safe to keep fixed length (Ethereum Secure Trie keys are 32-byte hashes)
    #     key_bytes = hex_to_bytes(k, KEY_LENGTH)  # Assuming KEY_LENGTH is 32

    #     # 2. VALUE: Decode dynamically! Do not force a length.
    #     # Strip the '0x' prefix if your JSON has it, then convert directly to bytes.
    #     clean_hex_val = v[2:] if v.startswith('0x') else v
    #     val_bytes = bytes.fromhex(clean_hex_val)

    #     # insert into tree
    #     data_tree.insert(key_bytes, val_bytes)

    # print("Inserted data into tree")

    # tree_data_path = f"{db_path}/data.json"
    # data_to_store = {}

    if TREE_TYPE == "verkle_eip6800":
        # EIP-6800 layout: one stem per account, BASIC_DATA and CODE_HASH leaves.
        # The inserted keys/values are stored per tree for prove_verify.py.
        data_to_store = {}
        for idx, (k, v) in enumerate(data.items()):
            if idx % 100 == 0:
                print(f" Inserting account of index: {idx}")
            stem, leaves = account_to_leaves(hex_to_bytes(k, KEY_LENGTH), hex_to_bytes(v, 0))
            data_tree.insert_stem(stem, leaves)
            for suffix, value in leaves.items():
                data_to_store["0x" + (stem + bytes([suffix])).hex()] = "0x" + value.hex()

        with open(Path(db_path) / "data.json", "w") as f:
            json.dump(data_to_store, f, indent=2)

        print("Inserted data into tree")
        return

    for idx, (k, v) in enumerate(data.items()):
        if idx % 100 == 0:
            print(f" Inserting key of index: {idx}")
            
        # 1. KEY: Original 32-byte hash
        key_bytes = hex_to_bytes(k, KEY_LENGTH)  

        # 2. VALUE: Decode dynamically
        clean_hex_val = v[2:] if v.startswith('0x') else v
        val_bytes = bytes.fromhex(clean_hex_val)

        # # =========================================================
        # # 3. CONDITIONAL LOGIC FOR VERKLE SUFFIX TREE
        # # =========================================================
        # if TREE_TYPE == "verkle":
        #     # The Ethereum EAS Tree uses the first 31 bytes as the stem
        #     base_key = key_bytes[:31]
            
        #     # Chop the RLP value into 31-byte scalars so they fit perfectly 
        #     # inside the BLS12-381 finite field without overflowing!
        #     CHUNK_SIZE = 31
        #     chunks = [val_bytes[i:i + CHUNK_SIZE] for i in range(0, len(val_bytes), CHUNK_SIZE)]
            
        #     for suffix_index, chunk in enumerate(chunks):
        #         # The 32nd byte becomes the suffix (0, 1, 2, 3...)
        #         suffix_byte = suffix_index.to_bytes(1, 'big')
        #         final_key = base_key + suffix_byte
                
        #         # Insert each chunk as its own adjacent leaf
        #         data_tree.insert(final_key, chunk)
        #         data_to_store[final_key.hex()] = chunk.hex()
                
        # =========================================================
        # STANDARD MERKLE TRIE
        # =========================================================
        # else:
            # Standard MPT can handle the full 80-byte value in a single leaf
        data_tree.insert(key_bytes, val_bytes)
    
    # if TREE_TYPE == "verkle":
    #     with open(tree_data_path, "w") as f:
    #         json.dump(data_to_store, f, indent=2)

    print("Inserted data into tree")

if __name__ == '__main__':
    test()