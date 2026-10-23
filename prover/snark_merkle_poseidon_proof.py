import json
import subprocess
import os
import math
import atexit
from registry.provers import BaseProver, register_prover
from tree.poseidon_merkle_tree import PoseidonMerklePatriciaTrie
from merkle.node import Node
from merkle.nibble_path import NibblePath
from zkSNARK.zk_encoder_decoder import _zk_encode, _zk_decode

# ==============================================================================
# CONFIGURATION
# ==============================================================================
CIRCUIT_DIR = "circuit_directory"
WITNESS_GEN = os.path.join(CIRCUIT_DIR, "mpt_batch_16_cpp", "mpt_batch_16")  # The Circom C++ executable for batched proofs
PROVER_BIN = "rapidsnark/package/bin/prover"
ZKEY_PATH = "mpt_batch_16.zkey"
BUILD_DIR = "snark_proofs"

FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MAX_DEPTH = 10
MAX_CHUNKS = 40
BATCH_SIZE = 4 # Poseidon Arity

# ------------------------------------------------------------------------------
# CHANGE THIS TO TEST DIFFERENT BATCH SIZES (Must match mpt.circom main component)
# ------------------------------------------------------------------------------
KEYS_BATCH_SIZE = 16

os.makedirs(BUILD_DIR, exist_ok=True)

def _pad_to_32_bytes(data: bytes) -> bytes:
    remainder = len(data) % 32
    if remainder != 0:
        data += b"\0" * (32 - remainder)
    return data

def _get_node_data(node) -> tuple[list[str], str]:
    enc = _pad_to_32_bytes(_zk_encode(node))
    chunks = [str(int.from_bytes(enc[j : j + 32], "big") % FIELD_MOD) for j in range(0, len(enc), 32)]
    actual_batches = str(math.ceil(len(chunks) / BATCH_SIZE))
    padded_chunks = chunks + ["0"] * (MAX_CHUNKS - len(chunks))
    if len(padded_chunks) > MAX_CHUNKS:
        raise ValueError(f"Node exceeds MAX_CHUNKS ({MAX_CHUNKS}).")
    return padded_chunks, actual_batches

@register_prover("zksnarkmerkle")
class ZKSnarkMerklePoseidonProof(BaseProver):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def generate_proof(self, tree: PoseidonMerklePatriciaTrie, keys: list[bytes]):
        values = [tree.get(key) for key in keys]
        proofs = [tree.get_proof_tree(key) for key in keys]
        root_hash = tree.root_hash()
        
        proof_files = []
        public_files = []

        # Process the list of keys in chunks of KEYS_BATCH_SIZE
        for chunk_idx, i in enumerate(range(0, len(keys), KEYS_BATCH_SIZE)):
            chunk_keys = keys[i : i + KEYS_BATCH_SIZE]
            chunk_values = values[i : i + KEYS_BATCH_SIZE]
            chunk_proofs = proofs[i : i + KEYS_BATCH_SIZE]

            # Pad the chunk by duplicating the last valid key if it's too small
            while len(chunk_keys) < KEYS_BATCH_SIZE:
                chunk_keys.append(chunk_keys[-1])
                chunk_values.append(chunk_values[-1])
                chunk_proofs.append(chunk_proofs[-1])

            # Initialize the batched JSON structure
            batch_input = {
                "root_pub": [], "length_pub": [], "val_pub_0": [], "val_pub_1": [], "val_pub_2": [],
                "actual_depth": [], "leaf_chunks": [], "leaf_batches": [],
                "node_types": [], "node_nibbles": [], "node_chunks": [], "node_batches": []
            }

            # Process every key in this batch
            for key, value, proof in zip(chunk_keys, chunk_values, chunk_proofs):
                root_pub = str(int.from_bytes(root_hash, "big") % FIELD_MOD)
                length_pub = str(len(value))
                
                padded_value = value.ljust(96, b"\0")
                val_pub_0 = str(int.from_bytes(padded_value[0:32],  "big") % FIELD_MOD)
                val_pub_1 = str(int.from_bytes(padded_value[32:64], "big") % FIELD_MOD)
                val_pub_2 = str(int.from_bytes(padded_value[64:96], "big") % FIELD_MOD)

                decoded_nodes = [_zk_decode(n) for n in proof]
                path_obj = NibblePath(key)
                
                leaf = decoded_nodes[-1]
                leaf_chunks, leaf_batches = _get_node_data(leaf)

                parent_nodes = decoded_nodes[:-1]
                actual_depth = len(parent_nodes)
                
                node_types, node_nibbles, node_chunks, node_batches = [], [], [], []
                
                current_depth = 0
                depths = []
                for node in parent_nodes:
                    depths.append(current_depth)
                    if isinstance(node, (Node.Leaf, Node.Extension)):
                        current_depth += len(node.path)
                    elif isinstance(node, Node.Branch):
                        current_depth += 1
                
                for parent, d in zip(reversed(parent_nodes), reversed(depths)):
                    chunks, batches = _get_node_data(parent)
                    
                    if isinstance(parent, Node.Extension):
                        node_types.append("0")
                        node_nibbles.append("0")
                    elif isinstance(parent, Node.Branch):
                        node_types.append("1")
                        node_nibbles.append(str(path_obj.at(d)))
                    else:
                        node_types.append("0")
                        node_nibbles.append("0")
                        
                    node_chunks.append(chunks)
                    node_batches.append(batches)

                padding_needed = MAX_DEPTH - actual_depth
                node_types.extend(["0"] * padding_needed)
                node_nibbles.extend(["0"] * padding_needed)
                node_batches.extend(["0"] * padding_needed)
                node_chunks.extend([["0"] * MAX_CHUNKS] * padding_needed)

                # Append data to the arrays
                batch_input["root_pub"].append(root_pub)
                batch_input["length_pub"].append(length_pub)
                batch_input["val_pub_0"].append(val_pub_0)
                batch_input["val_pub_1"].append(val_pub_1)
                batch_input["val_pub_2"].append(val_pub_2)
                batch_input["actual_depth"].append(str(actual_depth))
                batch_input["leaf_chunks"].append(leaf_chunks)
                batch_input["leaf_batches"].append(leaf_batches)
                batch_input["node_types"].append(node_types)
                batch_input["node_nibbles"].append(node_nibbles)
                batch_input["node_chunks"].append(node_chunks)
                batch_input["node_batches"].append(node_batches)

            # File Paths
            input_json_path = os.path.join(BUILD_DIR, f"input_batch_{chunk_idx}.json")
            witness_path = os.path.join(BUILD_DIR, f"witness_batch_{chunk_idx}.wtns")
            proof_path = os.path.join(BUILD_DIR, f"proof_batch_{chunk_idx}.json")
            public_path = os.path.join(BUILD_DIR, f"public_batch_{chunk_idx}.json")

            with open(input_json_path, "w") as f:
                json.dump(batch_input, f)

            print(f"\n[Batch {chunk_idx+1}] Generating Witness (Circom C++)...")
            subprocess.run([WITNESS_GEN, input_json_path, witness_path], check=True)

            print(f"[Batch {chunk_idx+1}] Generating Proof (RapidSnark)...")
            subprocess.run([PROVER_BIN, ZKEY_PATH, witness_path, proof_path, public_path], check=True)
            
            proof_files.append(proof_path)
            public_files.append(public_path)
        
        return proof_files, public_files

    def proof_size(self, proof_files, public_files) -> int:
        """
        Parses the JSON proof and physically packs the field elements into a 
        raw byte array exactly as they would be sent to an Ethereum EVM contract.
        Returns the true byte length.
        """
        total_size = 0
        for file_name in proof_files:
            if os.path.exists(file_name):
                with open(file_name, 'r') as f:
                    proof = json.load(f)
                    
                packed_bytes = bytearray()
                
                # 1. Pack pi_a (G1 Point: X, Y)
                packed_bytes.extend(int(proof["pi_a"][0]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_a"][1]).to_bytes(32, "big"))
                
                # 2. Pack pi_b (G2 Point: X_im, X_re, Y_im, Y_re)
                # Note: Ethereum's precompile expects the imaginary part first
                packed_bytes.extend(int(proof["pi_b"][0][1]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_b"][0][0]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_b"][1][1]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_b"][1][0]).to_bytes(32, "big"))
                
                # 3. Pack pi_c (G1 Point: X, Y)
                packed_bytes.extend(int(proof["pi_c"][0]).to_bytes(32, "big"))
                packed_bytes.extend(int(proof["pi_c"][1]).to_bytes(32, "big"))
                
                # The length of packed_bytes will be exactly 256
                total_size += len(packed_bytes)
                
        return total_size