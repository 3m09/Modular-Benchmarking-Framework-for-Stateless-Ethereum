"""
EIP-6800 shaped verkle tree with variable width w.

Node types:
    internal: w children indexed by log2(w)-bit digits of the stem,
              commitment over the child field elements
    leaf:     one per stem; holds up to 256 32-byte values and the suffix
              commitments (C1, C2 for w = 256).
              Leaf commitment = commit([1, stem, f(top_0), f(top_1), ..., 0, ...])

See verkle/eip6800.py for the value split and the suffix commitment levels.
"""
import os
import zlib
from py_ecc import optimized_bls12_381 as b

from registry.trees import TreeNode
from registry.trees import BaseTree, register_tree
from verkle.serialization import (
    serialize_array_node,
    deserialize_array_node,
    PREFIX_INTERNAL,
)
from verkle.eip6800 import (
    STEM_LENGTH,
    NUM_SUFFIXES,
    stem_path,
    suffix_level_sizes,
    build_suffix_commitments,
    leaf_commitment_values,
    suffix_opening_path,
    commit_sparse,
    update_commitment,
    commitment_to_field,
)
import plyvel

PREFIX_LEAF = b'\x03'


def _point_bytes(point):
    if point is None:
        return b'\x00'
    x_int = int(point[0])
    y_int = int(point[1])
    return b'\x01' + x_int.to_bytes(48, 'big') + y_int.to_bytes(48, 'big')


def _read_point(data, idx):
    if data[idx] == 0:
        return None, idx + 1
    x = int.from_bytes(data[idx + 1:idx + 49], 'big')
    y = int.from_bytes(data[idx + 49:idx + 97], 'big')
    return (b.FQ(x), b.FQ(y)), idx + 97


def serialize_leaf_node(commitment, stem, suffix_commitments, values):
    data = bytearray(PREFIX_LEAF)
    data += _point_bytes(commitment)
    data += stem
    data += len(suffix_commitments).to_bytes(1, 'big')
    for level in suffix_commitments:
        data += len(level).to_bytes(2, 'big')
        for c in level:
            data += _point_bytes(c)

    bitmap = bytearray(NUM_SUFFIXES // 8)
    value_data = b""
    for i, v in enumerate(values):
        if v is not None:
            bitmap[i // 8] |= (1 << (i % 8))
            value_data += v
    data += bytes(bitmap)
    data += value_data
    return zlib.compress(bytes(data), level=3)


def deserialize_leaf_node(data):
    idx = 1
    commitment, idx = _read_point(data, idx)
    stem = bytes(data[idx:idx + STEM_LENGTH])
    idx += STEM_LENGTH
    suffix_commitments = []
    num_levels = data[idx]
    idx += 1
    for _ in range(num_levels):
        count = int.from_bytes(data[idx:idx + 2], 'big')
        idx += 2
        level = []
        for _ in range(count):
            c, idx = _read_point(data, idx)
            level.append(c)
        suffix_commitments.append(level)

    bitmap = data[idx:idx + NUM_SUFFIXES // 8]
    idx += NUM_SUFFIXES // 8
    values = []
    for i in range(NUM_SUFFIXES):
        if (bitmap[i // 8] >> (i % 8)) & 1:
            values.append(bytes(data[idx:idx + 32]))
            idx += 32
        else:
            values.append(None)
    return commitment, stem, suffix_commitments, values


@register_tree("verkle_eip6800")
class VerkleTreeEIP6800(BaseTree):

    def __init__(self, width, db_path='./verkle', hash_fn=None, setup_object=None):
        suffix_level_sizes(width)  # validates the width
        super().__init__(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup_object)
        self.db = plyvel.DB(self.db_path + '/verkle_state_db', create_if_missing=True)
        self._root_ref_path = self.db_path + '/verkle_root_ref.bin'
        self._root_ref = open(self._root_ref_path, 'rb').read() if os.path.exists(self._root_ref_path) else None

        if self._root_ref:
            self.root = self._make_tree_node(self._root_ref)
        else:
            self.root = None

    # -------------------------------------------------------------------
    # Insertion
    # -------------------------------------------------------------------
    def insert(self, key, value):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise TypeError("Key must be exactly 32 bytes")
        self.insert_stem(bytes(key[:STEM_LENGTH]), {key[STEM_LENGTH]: value})

    def insert_stem(self, stem, leaves):
        """Writes several suffixes of one stem with a single commitment update."""
        if len(stem) != STEM_LENGTH:
            raise ValueError("Stem must be exactly 31 bytes")
        for suffix, value in leaves.items():
            if not isinstance(value, (bytes, bytearray)) or len(value) != 32:
                raise ValueError(f"Value for suffix {suffix} must be exactly 32 bytes")

        root = self.root if self.root is not None else self._new_internal()
        self.root = self._insert(root, 0, stem, leaves)

        with open(self._root_ref_path, 'wb') as f:
            f.write(self.root.value)
        self._root_ref = self.root.value

    def _insert(self, node, depth, stem, leaves):
        if node is None:
            node = self._new_leaf(stem)
            self._write_leaf_values(node, leaves)
            return node

        if node.type == 'leaf':
            if node.stem == stem:
                self._write_leaf_values(node, leaves)
                return node
            # Different stem: push the existing leaf one level down
            internal = self._new_internal()
            self._set_child(internal, stem_path(node.stem, self.width)[depth], node.value)
            return self._insert(internal, depth, stem, leaves)

        idx = stem_path(stem, self.width)[depth]
        child_ref = node.children[idx]
        child = self._make_tree_node(child_ref) if child_ref is not None else None
        new_child = self._insert(child, depth + 1, stem, leaves)
        self._set_child(node, idx, new_child.value)
        self._store_node(node)
        return node

    def _new_internal(self):
        node = TreeNode(self.width)
        node.type = 'internal'
        return node

    def _new_leaf(self, stem):
        node = TreeNode(NUM_SUFFIXES)
        node.type = 'leaf'
        node.stem = stem
        node.suffix_commitments = None
        return node

    def _set_child(self, node, idx, ref):
        old = int.from_bytes(node.children[idx], 'big') if node.children[idx] is not None else 0
        new = int.from_bytes(ref, 'big')
        node.commitment_to_children = update_commitment(node.commitment_to_children, idx, old, new, self.setup_object)
        node.children[idx] = ref
        node.value = commitment_to_field(node.commitment_to_children, self.setup_object).to_bytes(32, 'big')

    def _write_leaf_values(self, node, leaves):
        for suffix, value in leaves.items():
            node.children[suffix] = bytes(value)

        node.suffix_commitments = build_suffix_commitments(node.children, self.width, self.setup_object)
        node.commitment_to_children = commit_sparse(self.leaf_commitment_values(node), self.setup_object)
        node.value = commitment_to_field(node.commitment_to_children, self.setup_object).to_bytes(32, 'big')
        self._store_node(node)

    def leaf_commitment_values(self, node):
        return leaf_commitment_values(node.stem, node.suffix_commitments, self.width, self.setup_object)

    # -------------------------------------------------------------------
    # Retrieval
    # -------------------------------------------------------------------
    def get_path_nodes(self, stem):
        """Returns [root, internal..., leaf] for `stem`, or None if the stem is absent."""
        path = []
        digits = stem_path(stem, self.width)
        node = self.root
        depth = 0
        while node is not None:
            path.append(node)
            if node.type == 'leaf':
                return path if node.stem == stem else None
            child_ref = node.children[digits[depth]]
            if child_ref is None:
                return None
            node = self._make_tree_node(child_ref)
            depth += 1
        return None

    def get(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise TypeError("Key must be exactly 32 bytes")
        path = self.get_path_nodes(bytes(key[:STEM_LENGTH]))
        if path is None:
            return None
        return path[-1].children[key[STEM_LENGTH]]

    def get_proof_tree(self, key):
        """Commitments below the root: [internal..., leaf, suffix commitments top-down]."""
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise TypeError("Key must be exactly 32 bytes")
        path = self.get_path_nodes(bytes(key[:STEM_LENGTH]))
        if path is None:
            return None
        leaf = path[-1]
        positions, _ = suffix_opening_path(key[STEM_LENGTH], self.width)
        suffix_chain = [leaf.suffix_commitments[level][block] for level, (block, _) in enumerate(positions)]
        return [n.commitment_to_children for n in path[1:]] + suffix_chain[::-1]

    # -------------------------------------------------------------------
    # Storage and Deserialization
    # -------------------------------------------------------------------
    def _store_node(self, node):
        if node.type == 'internal':
            encoded = serialize_array_node(PREFIX_INTERNAL, node.commitment_to_children, node.children)
        else:
            encoded = serialize_leaf_node(node.commitment_to_children, node.stem, node.suffix_commitments, node.children)
        self.db.put(node.value, encoded)
        return node.value

    def _make_tree_node(self, reference):
        data = self.db.get(reference)
        if data is None:
            raise KeyError("Node not found in DB: " + reference.hex())
        data = zlib.decompress(data)
        prefix = data[0:1]

        if prefix == PREFIX_INTERNAL:
            node = TreeNode(self.width)
            node.type = 'internal'
            node.commitment_to_children, node.children = deserialize_array_node(data, 1)
        elif prefix == PREFIX_LEAF:
            node = TreeNode(NUM_SUFFIXES)
            node.type = 'leaf'
            node.commitment_to_children, node.stem, node.suffix_commitments, node.children = deserialize_leaf_node(data)
        else:
            raise ValueError(f"Unknown node prefix encountered: {prefix}")

        node.value = commitment_to_field(node.commitment_to_children, self.setup_object).to_bytes(32, 'big')
        if node.value != reference:
            print('Warning: computed node reference does not match stored reference!')
        return node
