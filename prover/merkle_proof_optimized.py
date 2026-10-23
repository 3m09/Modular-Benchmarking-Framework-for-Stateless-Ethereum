from registry.provers import BaseProver, register_prover
from tree.merkle_tree import MerklePatriciaTrie

@register_prover("merkle_optimized")
class MerkleProofGenerator(BaseProver):

    def __init__(self, setup_object=None):
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: MerklePatriciaTrie, keys: list[bytes]):
        """
        Generate optimized Merkle proofs for multiple keys with deduplication.
        
        Args:
            tree: MerklePatriciaTrie instance
            keys: List of keys to prove (bytes)
        
        Returns:
            deduplicated_proof: Dict with 'nodes' (unique RLP-encoded nodes) and 'proof_paths'
            witness: The root hash
        """
        self.tree = tree
        
        # Collect all RLP-encoded nodes and build deduplication map
        node_list = []           # List of unique RLP-encoded nodes
        node_map = {}            # Maps node hash to index in node_list
        proof_paths = []         # List of {key, node_indices}
        
        for key_idx, key in enumerate(keys):
            # Get the full proof path (list of RLP-encoded nodes)
            proof_path = tree.get_proof_tree(key)
            if proof_path is None:
                raise ValueError(f"Key not found in tree: {key.hex()}")
            
            key_node_indices = []
            
            for rlp_node in proof_path:
                # Create a hashable key for deduplication
                # Use the hash of the RLP-encoded node
                node_hash = hash(rlp_node)
                
                # Check if we've seen this node before
                if node_hash not in node_map:
                    node_map[node_hash] = len(node_list)
                    node_list.append(rlp_node)
                
                # Record the index of this node for this key's path
                key_node_indices.append(node_map[node_hash])
            
            # Store the node indices for this key
            proof_paths.append({
                'key_idx': key_idx,
                'node_indices': key_node_indices
            })
        
        # The "witness" is the root hash
        witness = tree.root_hash()
        
        # Return deduplicated proof
        deduplicated_proof = {
            'nodes': node_list,
            'proof_paths': proof_paths
        }
        
        return deduplicated_proof, witness
    
    def proof_size(self, deduplicated_proof, witness) -> int:
        """Calculate the size of the deduplicated proof in bytes."""
        node_list = deduplicated_proof['nodes']
        
        # Sum of all unique RLP-encoded node sizes
        nodes_size = sum(len(node) for node in node_list)
        
        # Size of proof paths (key + indices)
        proof_paths_size = 0
        for path_info in deduplicated_proof['proof_paths']:
            key_idx_size = len(path_info['key_idx'].to_bytes(4, byteorder='big'))  # Assuming key_idx fits in 4 bytes
            # Each index is stored as int (assume 2-4 bytes for typical trees)
            indices_size = len(path_info['node_indices']) * 2
            proof_paths_size += key_idx_size + indices_size
        
        # Size of witness (root hash)
        witness_size = len(witness)
        
        return nodes_size + proof_paths_size + witness_size