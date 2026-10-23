from registry.provers import BaseProver, register_prover
from tree.merkle_tree import MerklePatriciaTrie

@register_prover("merkle")
class MerkleProofGenerator(BaseProver):

    def __init__(self, setup_object=None):
        # Merkle doesn't need setup (unlike Verkle's KZG)
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: MerklePatriciaTrie, keys: list[bytes]):
        """
        Generate Merkle proofs for multiple keys.
        
        Args:
            tree: MerklePatriciaTrie instance
            keys: List of keys to prove (bytes)
        
        Returns:
            commitments: List of proof paths (one per key)
            witness: The root hash (single value for all keys)
        
        Each proof path is a list of RLP-encoded nodes from root to leaf.
        """
        # Collect proof for each key
        self.tree = tree
        commitments = []
        for key in keys:
            # get_proof_tree returns list of RLP-encoded nodes along the path
            proof_path = tree.get_proof_tree(key)
            if proof_path is None:
                raise ValueError(f"Key not found in tree: {key.hex()}")
            commitments.append(proof_path)
        
        # The "witness" in Merkle is the root hash
        # This is what gets committed to (like Verkle's polynomial commitment)
        witness = tree.root_hash()
        
        return commitments, witness
    
    def proof_size(self, commitments, witness) -> int:
        return self.tree.get_proof_size(commitments, witness)