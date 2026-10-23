import rlp
import os

from registry.trees import BaseTree, register_tree
#from registry.trees import TreeNode
from merkle.nibble_path import NibblePath
from merkle.node import Node
from merkle.hash import keccak_hash, poseidon_hash_bytes
from zkSNARK.zk_encoder_decoder import _zk_encode, _zk_decode
import plyvel


@register_tree("merkle")
class MerklePatriciaTrie(BaseTree):
    """
    MPT adapter that:
    - Conforms to the BaseTree interface (insert, get)
    - Internally uses the same logic as the previous MPT implementation:
        * NibblePath
        * Node (Leaf, Extension, Branch)
        * keccak_hash
        * RLP encoding
    - Uses an in-memory dict as storage (hash -> encoded node).
    """

    def __init__(self, width=16, db_path='./merkle', hash_fn="keccak", setup_object=None, secure=False, storage=None):
        # BaseTree doesn't have __init__, so we don't call super().__init__()
        # We manage our own state for MPT
        # if width != 16:
        #     raise ValueError("MerklePatriciaTrie is hex-based and requires width=16")

        super().__init__(width=width, db_path=db_path, hash_fn=hash_fn, setup_object=setup_object)

        # self._storage is currently unused because of plyvel DB usage
        # # Underlying node storage: hash -> encoded node
        # self._storage = storage if storage is not None else {}

        self.db = plyvel.DB(db_path + '/merkle_state_db', create_if_missing=True)

        # Secure mode means: hash keys with keccak256 before turning into nibbles.
        self._secure = secure

        # MPT root reference (bytes or None).
        # This is the "real" root of the trie; we mirror it in self.root.value.
        self._root_ref = open(db_path + '/merkle_root_ref.bin', 'rb').read() if os.path.exists(db_path + '/merkle_root_ref.bin') else None
        self.root.value = self._root_ref
        self.hash_fn_name = hash_fn
        self.hash = keccak_hash if hash_fn == "keccak" else poseidon_hash_bytes if hash_fn == "poseidon" else None
        if self.hash is None:
            raise ValueError("hash_fn must be 'keccak' or 'poseidon'")

    # -------------------------------------------------------------------------
    # Public API (BaseTree)
    # -------------------------------------------------------------------------

    def insert(self, key: bytes, value: bytes):
        """
        Insert or update a key–value pair in the MPT.

        key   : bytes           (already in final byte form, e.g., raw or RLP-encoded)
        value : bytes           (same idea)
        """
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes or bytearray")

        encoded_key = bytes(key)
        encoded_value = bytes(value)

        if self._secure:
            encoded_key = self.hash(encoded_key)

        path = NibblePath(encoded_key)
        new_root_ref = self._update(self._root_ref, path, encoded_value)

        self._root_ref = new_root_ref
        with open(self.db_path + '/merkle_root_ref.bin', 'wb') as f:
            f.write(self._root_ref)
        self.root.value = self._root_ref  # mirror into BaseTree root node

    def get(self, key: bytes) -> bytes:
        """
        Look up the value for a key in the MPT.

        key: bytes
        returns: bytes
        raises: KeyError if key is not present
        """
        if self._root_ref is None:
            raise KeyError("Empty trie")

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")

        encoded_key = bytes(key)
        if self._secure:
            encoded_key = self.hash(encoded_key)

        path = NibblePath(encoded_key)
        node = self._get(self._root_ref, path)

        # Expect node to be a Leaf or Branch with data
        if not hasattr(node, "data") or node.data is None:
            raise KeyError("Key not found (no data at terminal node)")

        return node.data

    def get_proof_tree(self, key: bytes):
        """
        Return a Merkle-Patricia proof for `key` as a list of RLP-encoded nodes,
        starting from the root node and following the path to the key.

        Each element of the returned list is:
            bytes  # RLP-encoded node (Leaf / Extension / Branch)

        Raises:
            KeyError if the key is not found.
        """
        if self._root_ref is None:
            raise KeyError("Empty trie")

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")

        encoded_key = bytes(key)
        if self._secure:
            encoded_key = self.hash(encoded_key)

        path = NibblePath(encoded_key)
        proof_nodes = []

        def _collect(node_ref, path_obj: NibblePath):
            """
            Recursively walk the trie like `_get`, but also push each encoded node
            onto `proof_nodes` as we go.
            """
            # Get the encoded form of this node (what's stored or inline)
            if len(node_ref) == 32:
                # the following line is commented out because of plyvel usage
                # encoded_node = self._storage[node_ref]
                encoded_node = self.db.get(node_ref)
            else:
                encoded_node = node_ref

            # Add this node's encoding to the proof
            proof_nodes.append(encoded_node)

            # # Decode into a structured Node instance
            # node = Node.decode(encoded_node)

            # Decode into a structured Node instance using the correct decoder
            if self.hash_fn_name == "poseidon":
                node = _zk_decode(encoded_node)
            else:
                node = Node.decode(encoded_node)

            # Leaf: must match exactly the remaining path
            if isinstance(node, Node.Leaf):
                if node.path == path_obj:
                    return node
                else:
                    raise KeyError(f"Key not found: leaf path mismatch (expected {path_obj}, got {node.path})")

            # If there is no more path to consume, check if we're at a valid terminal
            if len(path_obj) == 0:
                # For branch nodes with values at the node itself
                if isinstance(node, Node.Branch):
                    if node.data is not None:
                        return node
                    else:
                        raise KeyError("Key not found: no value at branch node")
                # Shouldn't reach here - path exhausted but not at leaf or branch
                raise KeyError("Key not found: path exhausted but not at valid terminal")

            # Extension: path must start with this extension's path
            elif isinstance(node, Node.Extension):
                if not path_obj.starts_with(node.path):
                    raise KeyError(f"Key not found: extension path mismatch (path {path_obj} doesn't start with {node.path})")
                # Consume the extension prefix and continue
                rest_path = path_obj.consume(len(node.path))
                return _collect(node.next_ref, rest_path)

            # Branch: choose child based on first nibble
            elif isinstance(node, Node.Branch):
                # Check if this branch has a value and path is exhausted
                if len(path_obj) == 0:
                    if node.data is not None:
                        return node
                    else:
                        raise KeyError("Key not found: no value at branch node")
                
                idx = path_obj.at(0)
                child_ref = node.branches[idx]
                if len(child_ref) == 0:
                    raise KeyError(f"Key not found: missing branch at index {idx}")
                rest_path = path_obj.consume(1)
                return _collect(child_ref, rest_path)

            else:
                raise TypeError(f"Unknown node type in get_proof_tree: {type(node)}")

        # Run the recursive collector
        final_node = _collect(self._root_ref, path)

        # Sanity check: ensure final node actually contains a value
        if not hasattr(final_node, "data") or final_node.data is None:
            raise KeyError("Key not found: no value at terminal node")

        return proof_nodes

    # -------------------------------------------------------------------------
    # Helper: MPT root hash (optional but useful)
    # -------------------------------------------------------------------------

    def root_hash(self) -> bytes:
        """
        Returns the hash of the trie's root node.

        For empty trie: Node.EMPTY_HASH
        For non-empty trie:
            - if root_ref is a 32-byte hash: that's the root hash
            - otherwise: keccak(root_ref)
        """
        if not self._root_ref:
            return Node.EMPTY_HASH
        elif len(self._root_ref) == 32:
            return self._root_ref
        else:
            return self.hash(self._root_ref)


    def _get_node(self, reference):
        data = self.db.get(reference)
        if data is None:
            raise KeyError("Node not found: " + reference.hex())
        if self.hash_fn_name == "poseidon":
            return _zk_decode(data)
        return Node.decode(data)


    def _get(self, node_ref, path: NibblePath):
        """
        Internal recursive lookup.
        """
        node = self._get_node(node_ref)

        # If path is empty, we stop here.
        if len(path) == 0:
            return node

        if type(node) is Node.Leaf:
            # Either correct leaf or wrong one.
            if node.path == path:
                return node

        elif type(node) is Node.Extension:
            # Extension: path must start with this prefix.
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                return self._get(node.next_ref, rest_path)

        elif type(node) is Node.Branch:
            # Branch: choose by first nibble.
            idx = path.at(0)
            branch_ref = node.branches[idx]
            if len(branch_ref) > 0:
                return self._get(branch_ref, path.consume(1))

        # If we reach here: key not found
        raise KeyError("Key not found in MPT")

    def _update(self, node_ref, path: NibblePath, value: bytes):
        """
        Internal recursive update method.
        Returns a new node reference (bytes).
        """
        # If there's no node here yet, create a Leaf.
        if not node_ref:
            return self._store_node(Node.Leaf(path, value))

        node = self._get_node(node_ref)

        # -------- Leaf case --------
        if type(node) == Node.Leaf:
            # Two possibilities:
            # 1. Path is exactly the same: just update value.
            # 2. Path differs: split into branch (and possibly extension).

            if node.path == path:
                node.data = value
                return self._store_node(node)

            # Split leaf: find common prefix between existing path and new path.
            common_prefix = path.common_prefix(node.path)

            # Cut off the common part.
            path.consume(len(common_prefix))
            node.path.consume(len(common_prefix))

            # Create a branch node with up to two leaves.
            branch_ref = self._create_branch_node(path, value, node.path, node.data)

            # If there was a non-empty common prefix, put an Extension node above branch.
            if len(common_prefix) != 0:
                return self._store_node(Node.Extension(common_prefix, branch_ref))
            else:
                return branch_ref

        # -------- Extension case --------
        elif type(node) == Node.Extension:
            # Two cases:
            # 1. New key starts with extension path: just go deeper.
            # 2. Otherwise, split extension.

            if path.starts_with(node.path):
                new_ref = self._update(node.next_ref, path.consume(len(node.path)), value)
                return self._store_node(Node.Extension(node.path, new_ref))

            # Split extension
            common_prefix = path.common_prefix(node.path)

            path.consume(len(common_prefix))
            node.path.consume(len(common_prefix))

            branches = [b''] * 16
            # If rest of path is empty, store value in Branch node's data.
            branch_value = value if len(path) == 0 else b''

            # Possibly add leaf for new value
            self._create_branch_leaf(path, value, branches)
            # Possibly add extension/leaf for the existing node's remainder
            self._create_branch_extension(node.path, node.next_ref, branches)

            branch_ref = self._store_node(Node.Branch(branches, branch_value))

            if len(common_prefix) != 0:
                return self._store_node(Node.Extension(common_prefix, branch_ref))
            else:
                return branch_ref

        # -------- Branch case --------
        elif type(node) == Node.Branch:
            # Two cases:
            # 1. No more path: update the value of this branch node.
            # 2. More path: recurse into the appropriate child.
            if len(path) == 0:
                return self._store_node(Node.Branch(node.branches, value))

            idx = path.at(0)
            new_ref = self._update(node.branches[idx], path.consume(1), value)
            node.branches[idx] = new_ref

            return self._store_node(node)

        else:
            raise TypeError("Unknown node type in _update")

    def _create_branch_node(self, path_a: NibblePath, value_a: bytes,
                            path_b: NibblePath, value_b: bytes):
        """
        Creates a Branch node with up to two leaves and maybe a direct value.
        Returns its reference.
        """
        assert len(path_a) != 0 or len(path_b) != 0

        branches = [b''] * 16

        branch_value = b''
        if len(path_a) == 0:
            branch_value = value_a
        elif len(path_b) == 0:
            branch_value = value_b

        self._create_branch_leaf(path_a, value_a, branches)
        self._create_branch_leaf(path_b, value_b, branches)

        return self._store_node(Node.Branch(branches, branch_value))

    def _create_branch_leaf(self, path: NibblePath, value: bytes, branches):
        """
        If path isn't empty, creates a Leaf node and stores its reference
        in the appropriate Branch child.
        """
        if len(path) > 0:
            idx = path.at(0)
            leaf_ref = self._store_node(Node.Leaf(path.consume(1), value))
            branches[idx] = leaf_ref

    def _create_branch_extension(self, path: NibblePath, next_ref, branches):
        """
        If needed, creates an Extension node and stores its reference
        in appropriate Branch child. Otherwise, stores provided reference directly.
        """
        assert len(path) >= 1, "Path for extension node should contain at least one nibble"

        if len(path) == 1:
            branches[path.at(0)] = next_ref
        else:
            idx = path.at(0)
            ref = self._store_node(Node.Extension(path.consume(1), next_ref))
            branches[idx] = ref

    # def _store_node(self, node):
    #     """
    #     Builds a reference from the node and, if needed, saves it in storage.
    #     Exactly like your previous repo's Node.into_reference logic.
    #     """
    #     reference = Node.into_reference(node)
    #     # If reference is a hash, store encoded node in the storage dict.
    #     if len(reference) == 32:
    #         self._storage[reference] = node.encode()
    #     return reference

    def _store_node(self, node):
        if self.hash_fn_name == "poseidon":
            encoded = _zk_encode(node)
            # You may also need to bypass Node.into_reference if it forces RLP
            reference = self.hash(encoded) 
        else:
            reference = Node.into_reference(node, self.hash_fn_name)
            encoded = node.encode()

        if len(reference) == 32:
            self.db.put(reference, encoded)
        return reference
    
    def get_proof_size(self, commitments, root_hash: bytes) -> int:
        size = 0
        for proof_path in commitments:
            for rlp_node in proof_path:
                size += len(rlp_node)
        size += len(root_hash)
        return size

