"""
Merkle Commitment Tree for ZK-STARK

Implements Merkle tree commitments for polynomial evaluations
used in the FRI protocol.
"""

import hashlib
from typing import List, Tuple
import numpy as np


def merkle_hash(left: bytes, right: bytes) -> bytes:
    """
    Hash two nodes to create parent node.
    
    Args:
        left, right: Child node hashes
        
    Returns:
        Parent node hash
    """
    return hashlib.sha256(left + right).digest()


def leaf_hash(data: bytes) -> bytes:
    """
    Hash leaf data.
    
    Args:
        data: Leaf data
        
    Returns:
        Leaf hash
    """
    return hashlib.sha256(b"LEAF:" + data).digest()


class MerkleTree:
    """
    Simple Merkle tree for polynomial commitments.
    
    Stores polynomial evaluations as leaves and provides
    authentication paths for specific indices.
    """
    
    def __init__(self, leaves: List[np.uint64]):
        """
        Build Merkle tree from leaf values.
        
        Args:
            leaves: List of field elements (polynomial evaluations)
        """
        self.n_leaves = len(leaves)
        
        # Ensure power of 2
        if self.n_leaves & (self.n_leaves - 1) != 0:
            raise ValueError("Number of leaves must be power of 2")
        
        # Build tree bottom-up
        self.layers = []
        
        # Leaf layer
        current_layer = [leaf_hash(int(leaf).to_bytes(8, 'big')) for leaf in leaves]
        self.layers.append(current_layer)
        
        # Internal layers
        while len(current_layer) > 1:
            next_layer = []
            for i in range(0, len(current_layer), 2):
                parent = merkle_hash(current_layer[i], current_layer[i+1])
                next_layer.append(parent)
            self.layers.append(next_layer)
            current_layer = next_layer
        
        self.root = current_layer[0]
    
    def get_authentication_path(self, index: int) -> List[bytes]:
        """
        Get Merkle authentication path for a leaf.
        
        Args:
            index: Leaf index
            
        Returns:
            List of sibling hashes from leaf to root
        """
        if index >= self.n_leaves:
            raise ValueError(f"Index {index} out of range")
        
        path = []
        current_idx = index
        
        for layer in self.layers[:-1]:  # Exclude root layer
            # Get sibling
            sibling_idx = current_idx ^ 1  # Flip last bit
            path.append(layer[sibling_idx])
            current_idx >>= 1
        
        return path
    
    def verify_path(self, index: int, value: np.uint64, path: List[bytes]) -> bool:
        """
        Verify authentication path.
        
        Args:
            index: Leaf index
            value: Claimed leaf value
            path: Authentication path
            
        Returns:
            True if path is valid
        """
        # Compute leaf hash
        current = leaf_hash(int(value).to_bytes(8, 'big'))
        current_idx = index
        
        # Hash up the tree
        for sibling in path:
            if current_idx & 1:  # Right child
                current = merkle_hash(sibling, current)
            else:  # Left child
                current = merkle_hash(current, sibling)
            current_idx >>= 1
        
        return current == self.root


class CommitmentTree:
    """
    Commitment tree for multiple polynomial columns.
    
    Used to commit to all trace columns simultaneously.
    """
    
    def __init__(self, columns: List[np.ndarray]):
        """
        Build commitment tree from multiple columns.
        
        Args:
            columns: List of polynomial evaluation arrays
        """
        self.n_columns = len(columns)
        self.n_rows = len(columns[0]) if columns else 0
        
        # Verify all columns same length
        for col in columns:
            if len(col) != self.n_rows:
                raise ValueError("All columns must have same length")
        
        # Combine columns row-wise and build Merkle tree
        combined_leaves = []
        for row_idx in range(self.n_rows):
            # Hash all column values in this row
            row_data = b""
            for col in columns:
                row_data += int(col[row_idx]).to_bytes(8, 'big')
            combined_leaves.append(hashlib.sha256(row_data).digest())
        
        # Build Merkle tree from combined leaves
        self.tree = self._build_tree(combined_leaves)
        self.root = self.tree[len(self.tree) - 1][0]
        
        # Store columns for query responses
        self.columns = columns
    
    def _build_tree(self, leaves: List[bytes]) -> List[List[bytes]]:
        """Build Merkle tree layers."""
        layers = [leaves]
        current = leaves
        
        while len(current) > 1:
            next_layer = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    parent = merkle_hash(current[i], current[i+1])
                else:
                    parent = current[i]
                next_layer.append(parent)
            layers.append(next_layer)
            current = next_layer
        
        return layers
    
    def get_query_response(self, index: int) -> Tuple[List[np.uint64], List[bytes]]:
        """
        Get values and authentication path for a query.
        
        Args:
            index: Row index to query
            
        Returns:
            (column_values, authentication_path)
        """
        # Get all column values at this index
        values = [col[index] for col in self.columns]
        
        # Get authentication path
        path = []
        current_idx = index
        
        for layer in self.tree[:-1]:
            sibling_idx = current_idx ^ 1
            if sibling_idx < len(layer):
                path.append(layer[sibling_idx])
            current_idx >>= 1
        
        return values, path
    
    def verify_query(self, index: int, values: List[np.uint64], path: List[bytes]) -> bool:
        """
        Verify query response.
        
        Args:
            index: Row index
            values: Claimed column values
            path: Authentication path
            
        Returns:
            True if valid
        """
        # Recompute leaf hash from values
        row_data = b""
        for val in values:
            row_data += int(val).to_bytes(8, 'big')
        current = hashlib.sha256(row_data).digest()
        
        # Hash up the tree
        current_idx = index
        for sibling in path:
            if current_idx & 1:
                current = merkle_hash(sibling, current)
            else:
                current = merkle_hash(current, sibling)
            current_idx >>= 1
        
        return current == self.root
