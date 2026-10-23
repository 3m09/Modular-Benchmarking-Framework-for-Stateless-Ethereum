import rlp
import os

from registry.trees import BaseTree, register_tree
from merkle.nibble_path import NibblePath
from merkle.node import Node
# from pysnark.runtime import LinComb, PrivVal
import plyvel

# # Poseidon (pysnark)
# try:
#     from pysnark.poseidon_hash import poseidon_hash
# except ImportError:
#     poseidon_hash = None
import poseidon

@register_tree("poseidon_merkle")
class PoseidonMerklePatriciaTrie(BaseTree):
    """
    Poseidon-based MPT adapter that:
    - Conforms to the BaseTree interface (insert, get)
    - Internally uses the same logic as the standard MPT:
        * NibblePath
        * Node (Leaf, Extension, Branch)
        * Poseidon hash instead of keccak
        * RLP encoding for nodes
    - Uses LevelDB as storage (hash -> encoded node).
    """

    def __init__(self, width=16, db_path="", hash_fn=None, setup_object=None, secure=False, storage=None):
        if width != 16:
            raise ValueError("MerklePatriciaTrie is hex-based and requires width=16")

        super().__init__(width=width, db_path=db_path, hash_fn=hash_fn, setup_object=setup_object)
        self.poseidon_hasher = poseidon.Poseidon(
            p=21888242871839275222246405745257275088548364400416034343698204186575808495617, 
            security_level=128, 
            alpha=5, 
            input_rate=1, 
            t=2
        )

        self.db = plyvel.DB('./merkle/poseidon_merkle_state_db', create_if_missing=True)

        # Secure mode means: hash keys with Poseidon before turning into nibbles.
        self._secure = secure

        # Root reference for this trie
        self._root_ref = open('./roots/poseidon_merkle_root_ref.bin', 'rb').read() \
            if os.path.exists('./roots/poseidon_merkle_root_ref.bin') else None
        self.root.value = self._root_ref

    # -------------------------------------------------------------------------
    # Hash helpers
    # -------------------------------------------------------------------------

    def _poseidon_hash_bytes(self, data: bytes) -> bytes:
        """
        Poseidon hash for bytes -> bytes (32 bytes).
        Adjust FIELD_MOD and BYTE_LEN to your curve if needed.
        """
        FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617  # BN128
        BYTE_LEN = 32

        x = int.from_bytes(data, "big") % FIELD_MOD

        hash_int = self.poseidon_hasher.run_hash([x])
        
        # 3. Return as 32 bytes
        return int(hash_int).to_bytes(BYTE_LEN, "big")
        # h = poseidon_hash([LinComb(x)])
        # return int(h[0].value).to_bytes(BYTE_LEN, "big")

    def _node_to_reference(self, node: Node) -> bytes:
        """
        Create a node reference:
        - If RLP-encoded node length < 32, store inline.
        - Else, store Poseidon hash of the encoded node.
        """
        encoded = node.encode()
        if len(encoded) < 32:
            return encoded
        return self._poseidon_hash_bytes(encoded)

    # -------------------------------------------------------------------------
    # Public API (BaseTree)
    # -------------------------------------------------------------------------

    def insert(self, key: bytes, value: bytes):
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("value must be bytes or bytearray")

        encoded_key = bytes(key)
        encoded_value = bytes(value)

        if self._secure:
            encoded_key = self._poseidon_hash_bytes(encoded_key)

        path = NibblePath(encoded_key)
        new_root_ref = self._update(self._root_ref, path, encoded_value)

        self._root_ref = new_root_ref
        with open('./roots/poseidon_merkle_root_ref.bin', 'wb') as f:
            f.write(self._root_ref)
        self.root.value = self._root_ref

    def get(self, key: bytes) -> bytes:
        if self._root_ref is None:
            raise KeyError("Empty trie")

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")

        encoded_key = bytes(key)
        if self._secure:
            encoded_key = self._poseidon_hash_bytes(encoded_key)

        path = NibblePath(encoded_key)
        node = self._get(self._root_ref, path)

        if not hasattr(node, "data") or node.data is None:
            raise KeyError("Key not found (no data at terminal node)")

        return node.data

    def get_proof_tree(self, key: bytes):
        if self._root_ref is None:
            raise KeyError("Empty trie")

        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes or bytearray")

        encoded_key = bytes(key)
        if self._secure:
            encoded_key = self._poseidon_hash_bytes(encoded_key)

        path = NibblePath(encoded_key)
        proof_nodes = []

        def _collect(node_ref, path_obj: NibblePath):
            if len(node_ref) == 32:
                encoded_node = self.db.get(node_ref)
            else:
                encoded_node = node_ref

            proof_nodes.append(encoded_node)

            node = Node.decode(encoded_node)

            if isinstance(node, Node.Leaf):
                if node.path == path_obj:
                    return node
                else:
                    raise KeyError(f"Key not found: leaf path mismatch (expected {path_obj}, got {node.path})")

            if len(path_obj) == 0:
                if isinstance(node, Node.Branch):
                    if node.data is not None:
                        return node
                    else:
                        raise KeyError("Key not found: no value at branch node")
                raise KeyError("Key not found: path exhausted but not at valid terminal")

            elif isinstance(node, Node.Extension):
                if not path_obj.starts_with(node.path):
                    raise KeyError(f"Key not found: extension path mismatch (path {path_obj} doesn't start with {node.path})")
                rest_path = path_obj.consume(len(node.path))
                return _collect(node.next_ref, rest_path)

            elif isinstance(node, Node.Branch):
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

        final_node = _collect(self._root_ref, path)

        if not hasattr(final_node, "data") or final_node.data is None:
            raise KeyError("Key not found: no value at terminal node")

        return proof_nodes

    # -------------------------------------------------------------------------
    #                            Helper: MPT root hash
    # -------------------------------------------------------------------------

    def root_hash(self) -> bytes:
        if not self._root_ref:
            return Node.EMPTY_HASH
        elif len(self._root_ref) == 32:
            return self._root_ref
        else:
            return self._poseidon_hash_bytes(self._root_ref)

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _get_node(self, reference):
        data = self.db.get(reference)
        if data is None:
            raise KeyError("Node not found: " + reference.hex())
        return Node.decode(data)

    def _get(self, node_ref, path: NibblePath):
        node = self._get_node(node_ref)

        if len(path) == 0:
            return node

        if type(node) is Node.Leaf:
            if node.path == path:
                return node

        elif type(node) is Node.Extension:
            if path.starts_with(node.path):
                rest_path = path.consume(len(node.path))
                return self._get(node.next_ref, rest_path)

        elif type(node) is Node.Branch:
            idx = path.at(0)
            branch_ref = node.branches[idx]
            if len(branch_ref) > 0:
                return self._get(branch_ref, path.consume(1))

        raise KeyError("Key not found in MPT")

    def _update(self, node_ref, path: NibblePath, value: bytes):
        if not node_ref:
            return self._store_node(Node.Leaf(path, value))

        node = self._get_node(node_ref)

        if type(node) == Node.Leaf:
            if node.path == path:
                node.data = value
                return self._store_node(node)

            common_prefix = path.common_prefix(node.path)

            path.consume(len(common_prefix))
            node.path.consume(len(common_prefix))

            branch_ref = self._create_branch_node(path, value, node.path, node.data)

            if len(common_prefix) != 0:
                return self._store_node(Node.Extension(common_prefix, branch_ref))
            else:
                return branch_ref

        elif type(node) == Node.Extension:
            if path.starts_with(node.path):
                new_ref = self._update(node.next_ref, path.consume(len(node.path)), value)
                return self._store_node(Node.Extension(node.path, new_ref))

            common_prefix = path.common_prefix(node.path)

            path.consume(len(common_prefix))
            node.path.consume(len(common_prefix))

            branches = [b''] * 16
            branch_value = value if len(path) == 0 else b''

            self._create_branch_leaf(path, value, branches)
            self._create_branch_extension(node.path, node.next_ref, branches)

            branch_ref = self._store_node(Node.Branch(branches, branch_value))

            if len(common_prefix) != 0:
                return self._store_node(Node.Extension(common_prefix, branch_ref))
            else:
                return branch_ref

        elif type(node) == Node.Branch:
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
        if len(path) > 0:
            idx = path.at(0)
            leaf_ref = self._store_node(Node.Leaf(path.consume(1), value))
            branches[idx] = leaf_ref

    def _create_branch_extension(self, path: NibblePath, next_ref, branches):
        assert len(path) >= 1, "Path for extension node should contain at least one nibble"

        if len(path) == 1:
            branches[path.at(0)] = next_ref
        else:
            idx = path.at(0)
            ref = self._store_node(Node.Extension(path.consume(1), next_ref))
            branches[idx] = ref

    def _store_node(self, node):
        reference = self._node_to_reference(node)
        if len(reference) == 32:
            encoded = node.encode()
            self.db.put(reference, encoded)
        return reference

    def get_proof_size(self, commitments, root_hash: bytes) -> int:
        size = 0
        for proof_path in commitments:
            print("proof path length:", len(proof_path))
            for rlp_node in proof_path:
                size += len(rlp_node)
        size += len(root_hash)
        return size