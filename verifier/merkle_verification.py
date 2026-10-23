from registry.verifiers import BaseVerifier, register_verifier
from merkle.hash import keccak_hash
from merkle.node import Node
from merkle.nibble_path import NibblePath

@register_verifier("merkle")
class MerkleProofVerifier(BaseVerifier):

    def __init__(self, setup_object=None):
        # Merkle doesn't need setup
        self.setup_object = setup_object

    def verify_proof(self, values: list[bytes], keys: list[bytes], root_hash: bytes, 
                     proof, paths=None, setup_object=None):
        """
        Verify Merkle proofs for multiple keys.
        
        Args:
            values: Expected values for each key (bytes)
            keys: Keys being proved (bytes)
            root_hash: Expected root hash of the tree
            proof: Tuple of (commitments, witness) from prover
            paths: Optional, not used for Merkle (kept for interface compatibility)
            setup_object: Not used for Merkle (only for Verkle)
        
        Returns:
            bool: True if all proofs are valid
        """
        commitments, witness = proof
        
        # Verify the witness matches the claimed root hash
        if witness != root_hash:
            print(f"Root hash mismatch: expected {root_hash.hex()[:16]}..., got {witness.hex()[:16]}...")
            return False
        
        # Verify each key's proof independently
        for proof_nodes, key, expected_value in zip(commitments, keys, values):
            if not self._verify_single_proof(proof_nodes, key, expected_value, root_hash):
                print(f"Failed to verify proof for key: {key.hex()[:16]}...")
                return False
        
        return True
    
    def _verify_single_proof(self, proof_nodes: list[bytes], key: bytes, 
                            expected_value: bytes, root_hash: bytes) -> bool:
        """
        Verify a single Merkle proof by:
        1. Walking through proof nodes from root to leaf
        2. Verifying hash consistency at each level
        3. Checking the final value matches
        """
        if not proof_nodes:
            return False
        
        # Convert key to nibble path for traversal (created inside verifier)
        path = NibblePath(key)
        
        # First node should hash to root_hash
        first_node_encoded = proof_nodes[0]
        computed_hash = keccak_hash(first_node_encoded) if len(first_node_encoded) >= 32 else first_node_encoded
        
        if len(computed_hash) == 32 and computed_hash != root_hash:
            print(f"  Root hash verification failed")
            print(f"    Expected: {root_hash.hex()[:32]}...")
            print(f"    Computed: {computed_hash.hex()[:32]}...")
            return False
        
        # Walk through the proof, verifying hash chain
        for i, encoded_node in enumerate(proof_nodes):
            # Decode the node
            try:
                node = Node.decode(encoded_node)
            except Exception as e:
                print(f"  Failed to decode node {i}: {e}")
                return False
            
            # Leaf node - final check
            if isinstance(node, Node.Leaf):
                # Path should match and value should match
                if node.path != path:
                    print(f"  Leaf path mismatch")
                    print(f"    Expected path: {path}")
                    print(f"    Leaf path: {node.path}")
                    return False
                if node.data != expected_value:
                    print(f"  Leaf value mismatch")
                    print(f"    Expected: {expected_value.hex()[:32]}...")
                    print(f"    Got: {node.data.hex()[:32]}...")
                    return False
                return True  # Success!
            
            # Extension node
            elif isinstance(node, Node.Extension):
                # Path must start with extension's path
                if not path.starts_with(node.path):
                    print(f"  Extension path mismatch at node {i}")
                    return False
                
                # Consume the prefix
                path = path.consume(len(node.path))
                
                # Verify next node reference (if not last node)
                if i + 1 < len(proof_nodes):
                    next_encoded = proof_nodes[i + 1]
                    expected_ref = Node.into_reference_from_encoded(next_encoded)
                    
                    if node.next_ref != expected_ref:
                        print(f"  Extension next_ref mismatch at node {i}")
                        return False
            
            # Branch node
            elif isinstance(node, Node.Branch):
                # If path is empty, check if value is stored here
                if len(path) == 0:
                    if node.data == expected_value:
                        return True
                    else:
                        print(f"  Branch value mismatch (empty path)")
                        return False
                
                # Get the branch index
                idx = path.at(0)
                branch_ref = node.branches[idx]
                
                if len(branch_ref) == 0:
                    print(f"  No child at branch index {idx}")
                    return False  # No child at this branch
                
                # Consume one nibble
                path = path.consume(1)
                
                # Verify next node reference (if not last node)
                if i + 1 < len(proof_nodes):
                    next_encoded = proof_nodes[i + 1]
                    expected_ref = Node.into_reference_from_encoded(next_encoded)
                    
                    if branch_ref != expected_ref:
                        print(f"  Branch ref mismatch at node {i}, branch {idx}")
                        print(f"    Expected: {expected_ref.hex()[:32] if len(expected_ref) > 0 else 'empty'}...")
                        print(f"    Got: {branch_ref.hex()[:32] if len(branch_ref) > 0 else 'empty'}...")
                        return False
        
        # If we get here without finding a leaf, verification failed
        print(f"  Reached end of proof without finding leaf")
        return False