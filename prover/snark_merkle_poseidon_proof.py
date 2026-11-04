import json
import subprocess
import os
from registry.provers import BaseProver, register_prover
from merkle.node import Node
from merkle.hash import poseidon_hash_bytes
from zkSNARK.zk_encoder_decoder import _zk_decode, leaf_public_words

# ==============================================================================
# CONFIGURATION (must match circuit_directory/mpt_batch_16.circom)
# ==============================================================================
CIRCUIT_DIR = "circuit_directory"
WITNESS_GEN = os.path.join(CIRCUIT_DIR, "mpt_batch_16_cpp", "mpt_batch_16")  # Circom C++ witness generator
PROVER_BIN = "rapidsnark/package/bin/prover"
ZKEY_PATH = "mpt_batch_16.zkey"
BUILD_DIR = "snark_proofs"

KEYS_BATCH_SIZE = 16   # keys per Groth16 proof
MAX_DEPTH = 10         # nodes above the leaf
LEAF_CHUNKS = 12       # 3 Poseidon batches
NODE_CHUNKS = 20       # 5 Poseidon batches

os.makedirs(BUILD_DIR, exist_ok=True)


def _words(encoded: bytes, n: int) -> list[str]:
    words = [str(int.from_bytes(encoded[i:i + 32], "big")) for i in range(0, len(encoded), 32)]
    if len(words) > n:
        raise ValueError("node does not fit the circuit")
    return words + ["0"] * (n - len(words))


def public_signals(root: bytes, keys: list[bytes], values: list[bytes]) -> list[str]:
    """
    Public inputs of one batch in circuit order: root, key_hi[16], key_lo[16],
    val_len[16], val[16][4]. Short batches repeat their last key, like the prover.
    """
    keys, values = list(keys), list(values)
    while len(keys) < KEYS_BATCH_SIZE:
        keys.append(keys[-1])
        values.append(values[-1])
    words = [leaf_public_words(k, v) for k, v in zip(keys, values)]
    signals = [int.from_bytes(root, "big")]
    signals += [w[0] for w in words] + [w[1] for w in words] + [w[2] for w in words]
    signals += [x for w in words for x in w[3:]]
    return [str(s) for s in signals]


@register_prover("zksnarkmerkle")
class ZKSnarkMerklePoseidonProof(BaseProver):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def _path_input(self, proof_nodes: list[bytes]):
        """Private witness for one key: leaf words and the parents, leaf side first."""
        if len(proof_nodes) - 1 > MAX_DEPTH:
            raise ValueError(f"path deeper than MAX_DEPTH={MAX_DEPTH}")
        leaf_chunks = _words(proof_nodes[-1], LEAF_CHUNKS)

        node_types, node_nibbles, node_chunks = [], [], []
        child_ref = None
        for encoded in reversed(proof_nodes):
            node = _zk_decode(encoded)
            if child_ref is not None:
                if isinstance(node, Node.Branch):
                    node_types.append("1")
                    node_nibbles.append(str(node.branches.index(child_ref)))
                else:
                    node_types.append("0")
                    node_nibbles.append("0")
                node_chunks.append(_words(encoded, NODE_CHUNKS))
            # every Poseidon node is referenced by its 32-byte hash
            child_ref = poseidon_hash_bytes(encoded)

        depth = len(node_types)
        pad = MAX_DEPTH - depth
        return {
            "actual_depth": str(depth),
            "leaf_chunks": leaf_chunks,
            "node_types": node_types + ["0"] * pad,
            "node_nibbles": node_nibbles + ["0"] * pad,
            "node_chunks": node_chunks + [["0"] * NODE_CHUNKS] * pad,
        }

    def generate_proof(self, tree, keys: list[bytes]):
        if getattr(tree, "hash_fn_name", None) != "poseidon" or getattr(tree, "width", None) != 16:
            raise ValueError("zk-SNARK backend requires a hexary Poseidon MPT")
        root = tree.root_hash()
        values = [tree.get(key) for key in keys]
        paths = [self._path_input(tree.get_proof_tree(key)) for key in keys]

        proof_files = []
        for chunk_idx, i in enumerate(range(0, len(keys), KEYS_BATCH_SIZE)):
            chunk = list(range(i, min(i + KEYS_BATCH_SIZE, len(keys))))
            while len(chunk) < KEYS_BATCH_SIZE:     # pad by repeating the last key
                chunk.append(chunk[-1])

            pub = public_signals(root, [keys[j] for j in chunk], [values[j] for j in chunk])
            n = KEYS_BATCH_SIZE
            batch_input = {
                "root": pub[0],
                "key_hi": pub[1:1 + n],
                "key_lo": pub[1 + n:1 + 2 * n],
                "val_len": pub[1 + 2 * n:1 + 3 * n],
                "val": [pub[1 + 3 * n + 4 * k:1 + 3 * n + 4 * k + 4] for k in range(n)],
            }
            for field in ("actual_depth", "leaf_chunks", "node_types", "node_nibbles", "node_chunks"):
                batch_input[field] = [paths[j][field] for j in chunk]

            input_json_path = os.path.join(BUILD_DIR, f"input_batch_{chunk_idx}.json")
            witness_path = os.path.join(BUILD_DIR, f"witness_batch_{chunk_idx}.wtns")
            proof_path = os.path.join(BUILD_DIR, f"proof_batch_{chunk_idx}.json")
            public_path = os.path.join(BUILD_DIR, f"public_batch_{chunk_idx}.json")

            with open(input_json_path, "w") as f:
                json.dump(batch_input, f)
            subprocess.run([WITNESS_GEN, input_json_path, witness_path], check=True, capture_output=True)
            subprocess.run([PROVER_BIN, ZKEY_PATH, witness_path, proof_path, public_path], check=True, capture_output=True)

            with open(proof_path) as f:
                proof_files.append(json.load(f))

        # Only the Groth16 proofs are returned; public inputs are recomputed by the verifier.
        return proof_files, root

    def proof_size(self, proofs, root) -> int:
        """Uncompressed BN254 Groth16 proof as sent to the EVM: A (G1), B (G2), C (G1) = 256 bytes each."""
        total_size = 0
        for proof in proofs:
            packed = bytearray()
            for coord in proof["pi_a"][:2]:
                packed += int(coord).to_bytes(32, "big")
            for pair in proof["pi_b"][:2]:
                packed += int(pair[1]).to_bytes(32, "big") + int(pair[0]).to_bytes(32, "big")
            for coord in proof["pi_c"][:2]:
                packed += int(coord).to_bytes(32, "big")
            total_size += len(packed)
        return total_size
