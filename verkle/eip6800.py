"""
EIP-6800 helpers: account leaf encoding, leaf value splitting, the
width-generic suffix commitments, and sparse KZG commitments in Lagrange form.

Account layout (256 suffixes per stem):
    suffix 0 -> BASIC_DATA: version(1) | reserved(4) | code_size(3) | nonce(8) | balance(16)
    suffix 1 -> CODE_HASH:  32-byte keccak of the account code

Leaf node with tree width w:
    Each 32-byte value at suffix s becomes two field elements at positions
    2s and 2s+1 of a 512-element vector E (see split_leaf_value).
    Level 0 commits E in blocks of w. While there are more blocks than the
    w - 2 free slots of the leaf commitment, the field images of the blocks
    are committed again in blocks of w.
    Leaf commitment = commit([1, stem, f(top_0), f(top_1), ..., 0, ...])
    For w = 256 this is exactly EIP-6800: level 0 = [C1, C2].

Internal nodes branch on log2(w) bits of the 248-bit stem.

Simplifications (must be stated when reporting results):
    - The stem is keccak(address)[:31] (secure-trie key) instead of
      pedersen_hash(address, tree_index)[:31], because the dataset only
      contains hashed addresses.
    - code_size is 0 for every account, because bytecode is not in the dataset.
    - Storage slots and code chunks are not included.
    - Commitments are KZG over BLS12-381 instead of Pedersen/IPA over Bandersnatch.
    - For w != 256 the suffix commitments are a generalisation of C1/C2.
"""
import hashlib
import math
import rlp
from py_ecc import optimized_bls12_381 as b
from verkle.hash_scheme import hash_point_to_field, generate_root_bytes

BASIC_DATA_LEAF_KEY = 0
CODE_HASH_LEAF_KEY = 1

STEM_LENGTH = 31
NUM_SUFFIXES = 256
NUM_LEAF_ELEMENTS = 2 * NUM_SUFFIXES
LEAF_MARKER = 2 ** 128

BASIC_DATA_VERSION = 0


def decode_account_rlp(value_bytes):
    """Decodes a secure-trie account value [nonce, balance, storageRoot, codeHash]."""
    nonce, balance, storage_root, code_hash = rlp.decode(value_bytes)
    return {
        'nonce': int.from_bytes(nonce, 'big'),
        'balance': int.from_bytes(balance, 'big'),
        'storage_root': storage_root,
        'code_hash': code_hash,
    }


def encode_basic_data(nonce, balance, code_size=0, version=BASIC_DATA_VERSION):
    if nonce >= 2 ** 64 or balance >= 2 ** 128 or code_size >= 2 ** 24:
        raise ValueError("Account field does not fit the BASIC_DATA layout")
    return (
        version.to_bytes(1, 'big')
        + b'\x00' * 4
        + code_size.to_bytes(3, 'big')
        + nonce.to_bytes(8, 'big')
        + balance.to_bytes(16, 'big')
    )


def account_to_leaves(trie_key, account_rlp):
    """
    Maps one secure-trie account to its EIP-6800 leaves.
    Returns (stem, {suffix: 32-byte value}). storageRoot is dropped.
    """
    account = decode_account_rlp(account_rlp)
    stem = bytes(trie_key[:STEM_LENGTH])
    code_hash = account['code_hash'].rjust(32, b'\x00')
    leaves = {
        BASIC_DATA_LEAF_KEY: encode_basic_data(account['nonce'], account['balance']),
        CODE_HASH_LEAF_KEY: code_hash,
    }
    return stem, leaves


def split_leaf_value(value):
    """
    Splits a 32-byte leaf value into two field elements (EIP-6800):
    lower 16 bytes (little endian) + 2^128 marker, upper 16 bytes (little endian).
    The marker distinguishes a stored zero value from an empty slot.
    """
    if len(value) != 32:
        raise ValueError("Leaf values must be exactly 32 bytes")
    lower = int.from_bytes(value[:16], 'little') + LEAF_MARKER
    upper = int.from_bytes(value[16:], 'little')
    return lower, upper


# -----------------------------------------------------------------------
# Stem path (internal nodes)
# -----------------------------------------------------------------------
def stem_path(stem, width):
    """Splits the 248-bit stem into log2(width)-bit digits, zero-padded at the front."""
    bits = int(math.log2(width))
    if 2 ** bits != width:
        raise ValueError("Tree width must be a power of 2.")
    num_digits = -(-STEM_LENGTH * 8 // bits)
    stem_int = int.from_bytes(stem, 'big')
    return tuple(
        (stem_int >> ((num_digits - 1 - i) * bits)) & (width - 1)
        for i in range(num_digits)
    )


# -----------------------------------------------------------------------
# Suffix commitments (leaf node)
# -----------------------------------------------------------------------
def suffix_level_sizes(width):
    """Number of commitments per suffix level, bottom-up. w=256 -> [2], w=16 -> [32, 2]."""
    if width < 4:
        raise ValueError("Tree width must be at least 4")
    sizes = [-(-NUM_LEAF_ELEMENTS // width)]
    while sizes[-1] > width - 2:
        sizes.append(-(-sizes[-1] // width))
    return sizes


def leaf_elements(values):
    """512-element vector E: E[2s], E[2s+1] = split value at suffix s (0 if empty)."""
    elements = [0] * NUM_LEAF_ELEMENTS
    for s, value in enumerate(values):
        if value is not None:
            elements[2 * s], elements[2 * s + 1] = split_leaf_value(value)
    return elements


def _blocks(vector, width):
    return [
        vector[i:i + width] + [0] * (width - len(vector[i:i + width]))
        for i in range(0, len(vector), width)
    ]


def build_suffix_commitments(values, width, setup_object):
    """Commits every suffix level. Returns a list of levels, each a list of points (or None)."""
    levels = []
    current = leaf_elements(values)
    for _ in suffix_level_sizes(width):
        level = [commit_sparse(block, setup_object) for block in _blocks(current, width)]
        levels.append(level)
        current = [commitment_to_field(c, setup_object) for c in level]
    return levels


def suffix_level_evals(values, suffix_commitments, width, setup_object):
    """Evaluation vectors of every suffix commitment, same shape as suffix_commitments."""
    evals = []
    current = leaf_elements(values)
    for level in suffix_commitments:
        evals.append(_blocks(current, width))
        current = [commitment_to_field(c, setup_object) for c in level]
    return evals


def leaf_commitment_values(stem, suffix_commitments, width, setup_object):
    evals = [0] * width
    evals[0] = 1
    evals[1] = int.from_bytes(stem, 'big')
    for j, c in enumerate(suffix_commitments[-1]):
        evals[2 + j] = commitment_to_field(c, setup_object)
    return evals


def suffix_opening_path(suffix, width):
    """
    Bottom-up positions of `suffix` in the suffix commitments: [(block, index), ...]
    where `index` is the position inside that level's commitment. Level 0's index
    is the lower half (the upper half is index + 1). Also returns the slot in
    the leaf commitment that holds the top-level commitment.
    """
    positions = []
    pos = 2 * suffix
    for _ in suffix_level_sizes(width):
        positions.append((pos // width, pos % width))
        pos = pos // width
    return positions, 2 + pos


# -----------------------------------------------------------------------
# Commitments
# -----------------------------------------------------------------------
def commit_sparse(evals, setup_object):
    """
    KZG commitment in Lagrange form: sum(v_i * [L_i(s)]G1) over non-zero v_i.
    Equal to commit() from commitment_scheme.py, without the FFT and zero terms.
    Returns None for the all-zero vector (point at infinity).
    """
    lagrange_g1 = setup_object.setup[2]
    acc = b.Z1
    for i, v in enumerate(evals):
        v %= setup_object.MODULUS
        if v:
            acc = b.add(acc, b.multiply(lagrange_g1[i], v))
    if b.is_inf(acc):
        return None
    return b.normalize(acc)


def update_commitment(commitment, idx, old_value, new_value, setup_object):
    """C' = C + (new - old) * [L_idx(s)]G1. `commitment` may be None (empty)."""
    delta = (new_value - old_value) % setup_object.MODULUS
    acc = b.Z1 if commitment is None else (commitment[0], commitment[1], b.FQ.one())
    if delta:
        acc = b.add(acc, b.multiply(setup_object.setup[2][idx], delta))
    if b.is_inf(acc):
        return None
    return b.normalize(acc)


def commitment_to_field(commitment, setup_object):
    """Maps a commitment to a field element; the empty commitment maps to 0."""
    if commitment is None:
        return 0
    return hash_point_to_field(commitment, setup_object.MODULUS)


def derive_opening_challenge(root, openings, curve_order):
    """
    Fiat-Shamir challenge over every opening (commitment, index, claimed value).
    Prover and verifier must build `openings` in the same order.
    """
    h = hashlib.sha256()
    h.update(generate_root_bytes(root))
    for commitment, idx, y in openings:
        h.update(generate_root_bytes(commitment))
        h.update(idx.to_bytes(2, 'big'))
        h.update((y % curve_order).to_bytes(32, 'big'))
    return int.from_bytes(h.digest(), 'big') % curve_order
