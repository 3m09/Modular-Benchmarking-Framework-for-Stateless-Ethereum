"""
Field-native node encoding for the Poseidon MPT used by the zk-SNARK backend.

Every node is a sequence of 32-byte big-endian words and every word is smaller
than the BN254 scalar field modulus, so hashing a word as a field element is
injective (no reduction mod p). The words are:

    Leaf      [1, remaining_len, key_hi, key_lo, value_len, v0, v1, v2, v3]
    Extension [2, path_len, path_hi, path_lo, next_ref]
    Branch    [3, child_0, ..., child_15, 0]

key_hi/key_lo are the two 16-byte halves of the full 32-byte key, so a leaf
commits to its own key and the circuit can bind the public key to it.
v0..v3 hold the value in 31-byte chunks (at most 124 bytes; an RLP account is
at most 90). Extension paths are nibble-packed into 32 bytes and split into
16-byte halves. Child references are Poseidon outputs (already < p).
Branch nodes never hold values: all keys are 32 bytes long.
"""
from merkle.node import Node
from merkle.nibble_path import NibblePath

FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
KEY_DIGITS = 64
VALUE_CHUNK = 31
VALUE_CHUNKS = 4
WIDTH = 16

LEAF, EXTENSION, BRANCH = 1, 2, 3


def _word(x: int) -> bytes:
    if not 0 <= x < FIELD_MOD:
        raise ValueError("word is not a canonical field element")
    return x.to_bytes(32, 'big')


def _pack_nibbles(digits) -> bytes:
    """Packs up to 64 nibbles, most-significant first, into 32 bytes (zero padded)."""
    digits = list(digits) + [0] * (KEY_DIGITS - len(digits))
    return bytes(digits[i] * 16 + digits[i + 1] for i in range(0, KEY_DIGITS, 2))


def _unpack_nibbles(data: bytes, length: int):
    return [n for b in data for n in (b >> 4, b & 15)][:length]


def _split_value(value: bytes):
    if len(value) > VALUE_CHUNK * VALUE_CHUNKS:
        raise ValueError("value does not fit the leaf encoding")
    padded = value.ljust(VALUE_CHUNK * VALUE_CHUNKS, b'\0')
    return [int.from_bytes(padded[i:i + VALUE_CHUNK], 'big')
            for i in range(0, len(padded), VALUE_CHUNK)]


def leaf_public_words(key: bytes, value: bytes):
    """(key_hi, key_lo, value_len, v0..v3): the per-key public inputs of the circuit."""
    if len(key) != 32:
        raise ValueError("keys must be 32 bytes")
    return [int.from_bytes(key[:16], 'big'), int.from_bytes(key[16:], 'big'), len(value)] + _split_value(value)


def _full_key(path: NibblePath) -> bytes:
    # Leaf paths always keep the full key digits; only the offset moves (see _zk_decode).
    digits = path._digits
    if path._width != WIDTH or len(digits) != KEY_DIGITS:
        raise ValueError("Poseidon MPT leaves need the full 32-byte key")
    return _pack_nibbles(digits)


def _zk_encode(node) -> bytes:
    if isinstance(node, Node.Leaf):
        words = [LEAF, len(node.path)] + leaf_public_words(_full_key(node.path), node.data or b'')
        return b''.join(_word(w) for w in words)

    if isinstance(node, Node.Extension):
        path = [node.path.at(i) for i in range(len(node.path))]
        packed = _pack_nibbles(path)
        return b''.join([
            _word(EXTENSION),
            _word(len(path)),
            _word(int.from_bytes(packed[:16], 'big')),
            _word(int.from_bytes(packed[16:], 'big')),
            node.next_ref.rjust(32, b'\0'),
        ])

    if isinstance(node, Node.Branch):
        if node.data:
            raise ValueError("Poseidon MPT branch nodes cannot hold values")
        if len(node.branches) != WIDTH:
            raise ValueError("Poseidon MPT is hexary")
        children = [c.rjust(32, b'\0') if c else b'\0' * 32 for c in node.branches]
        return _word(BRANCH) + b''.join(children) + _word(0)

    raise TypeError("Unknown node type")


def _zk_decode(data: bytes):
    words = [data[i:i + 32] for i in range(0, len(data), 32)]
    node_type = int.from_bytes(words[0], 'big')

    if node_type == LEAF:
        remaining = int.from_bytes(words[1], 'big')
        key = words[2][16:] + words[3][16:]
        value_len = int.from_bytes(words[4], 'big')
        value = b''.join(w[1:] for w in words[5:5 + VALUE_CHUNKS])[:value_len]
        digits = _unpack_nibbles(key, KEY_DIGITS)
        return Node.Leaf(NibblePath(digits, offset=KEY_DIGITS - remaining, width=WIDTH), value)

    if node_type == EXTENSION:
        length = int.from_bytes(words[1], 'big')
        packed = words[2][16:] + words[3][16:]
        path = NibblePath(_unpack_nibbles(packed, length), width=WIDTH)
        return Node.Extension(path, words[4])

    if node_type == BRANCH:
        branches = [w if w != b'\0' * 32 else b'' for w in words[1:1 + WIDTH]]
        return Node.Branch(branches, b'')

    raise ValueError("Unknown node type")
