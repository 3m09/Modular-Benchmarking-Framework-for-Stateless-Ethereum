from registry.verifiers import BaseVerifier, register_verifier
from merkle.hash import keccak_hash
from merkle.node import Node
from merkle.nibble_path import NibblePath

@register_verifier("merkle_optimized")
class MerkleProofVerifier(BaseVerifier):

    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def verify_proof(self, values: list[bytes], keys: list[bytes], root_hash: bytes, 
                     proof, paths=None, setup_object=None):
        """
        Verify optimized Merkle proofs with deduplicated nodes.
        
        Args:
            values: Expected values for each key (bytes)
            keys: Keys being proved (bytes)
            root_hash: Expected root hash of the tree
            proof: Tuple of (deduplicated_proof, witness)
            paths: Optional, not used for Merkle
            setup_object: Not used for Merkle
        
        Returns:
            bool: True if all proofs are valid
        """
        deduplicated_proof, witness = proof
        node_list = deduplicated_proof['nodes']
        proof_paths = deduplicated_proof['proof_paths']
        
        # Verify the witness matches the claimed root hash
        if witness != root_hash:
            print(f"Root hash mismatch: expected {root_hash.hex()[:16]}..., got {witness.hex()[:16]}...")
            return False
        
        # Build a map from key to node_indices for fast lookup
        key_to_path_info = {}
        for path_info in proof_paths:
            key_idx = path_info['key_idx']
            key_to_path_info[keys[key_idx]] = path_info
        
        # Verify each key's proof independently
        for key, expected_value in zip(keys, values):
            path_info = key_to_path_info[key]
            node_indices = path_info['node_indices']
            
            # Reconstruct the proof nodes from indices
            proof_nodes = [node_list[idx] for idx in node_indices]
            
            if not self._verify_single_proof(proof_nodes, key, expected_value, root_hash):
                print(f"Failed to verify proof for key: {key.hex()[:16]}...")
                return False
        
        return True
    
    def _verify_single_proof(self, proof_nodes: list[bytes], key: bytes, 
                            expected_value: bytes, root_hash: bytes) -> bool:
        """
        Verify a single Merkle proof by walking through nodes from root to leaf.
        """
        if not proof_nodes:
            return False
        
        # Convert key to nibble path for traversal
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
                if node.path != path:
                    print(f"  Leaf path mismatch")
                    return False
                if node.data != expected_value:
                    print(f"  Leaf value mismatch")
                    return False
                return True
            
            # Extension node
            elif isinstance(node, Node.Extension):
                if not path.starts_with(node.path):
                    print(f"  Extension path mismatch at node {i}")
                    return False
                
                path = path.consume(len(node.path))
                
                # Verify next node reference
                if i + 1 < len(proof_nodes):
                    next_encoded = proof_nodes[i + 1]
                    expected_ref = Node.into_reference_from_encoded(next_encoded)
                    
                    if node.next_ref != expected_ref:
                        print(f"  Extension next_ref mismatch at node {i}")
                        return False
            
            # Branch node
            elif isinstance(node, Node.Branch):
                if len(path) == 0:
                    if node.data == expected_value:
                        return True
                    else:
                        print(f"  Branch value mismatch (empty path)")
                        return False
                
                idx = path.at(0)
                branch_ref = node.branches[idx]
                
                if len(branch_ref) == 0:
                    print(f"  No child at branch index {idx}")
                    return False
                
                path = path.consume(1)
                
                # Verify next node reference
                if i + 1 < len(proof_nodes):
                    next_encoded = proof_nodes[i + 1]
                    expected_ref = Node.into_reference_from_encoded(next_encoded)
                    
                    if branch_ref != expected_ref:
                        print(f"  Branch ref mismatch at node {i}, branch {idx}")
                        return False
        
        print(f"  Reached end of proof without finding leaf")
        return False