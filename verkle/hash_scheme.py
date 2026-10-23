import hashlib
from typing import Tuple
from py_ecc import optimized_bls12_381 as b

# Just sha256
def hash(x):
    return hashlib.sha256(x).digest()

# Hashes a curve point to a number
def hash_point_to_field(pt, MODULUS):
    assert len(pt) == 2
    return int.from_bytes(hash(str(pt).encode('utf-8')), 'big') % MODULUS

"""
Utility functions to serialize a 2D G1 commitment point into a canonical byte string.

This file provides `generate_root_bytes` which accepts a "2D root commitment"
(i.e. an affine G1 point like (x, y) returned by py_ecc.normalize) and returns
a deterministic bytestring suitable for Fiat–Shamir hashing.

The function is robust to coordinates being ints or py_ecc FQ objects (which
expose the integer as `.n`). It produces an uncompressed encoding with a 0x04
prefix by default, but can also produce a compressed encoding (0x02/0x03 + x)
if compressed=True.

Both prover and verifier must use the exact same serialization (same prefix,
same coordinate byte length) for the Fiat–Shamir challenge to match.

Example:
    from py_ecc import optimized_bls12_381 as b
    p = b.normalize(b.multiply(b.G1, 12345))
    rb = generate_root_bytes(p)
    # rb is bytes that you can feed into hashlib.sha256(...)
"""

Point2D = Tuple[object, object]  # coordinates may be int or FQ-like objects with .n


def _coord_to_int(c) -> int:
    """Convert a coordinate (int or FQ-like) to a plain Python int."""
    if hasattr(c, "n"):
        return int(c.n)
    try:
        return int(c)
    except Exception as e:
        raise TypeError(f"Unsupported coordinate type: {type(c)}") from e


def _fixed_length_bytes(i: int, length: int) -> bytes:
    """Encode integer `i` to big-endian bytes using exactly `length` bytes."""
    if i < 0:
        raise ValueError("Cannot encode negative integers")
    # Ensure the integer fits in the provided fixed length.
    needed = (i.bit_length() + 7) // 8
    if needed > length:
        raise OverflowError(
            f"Integer requires {needed} bytes but fixed length is {length}. "
            f"This likely means the fixed length was computed from the wrong modulus."
        )
    return i.to_bytes(length, byteorder="big")


def generate_root_bytes(
    root_commitment: Point2D,
    compressed: bool = False,
    include_prefix: bool = True,
    field_modulus: int = None,
) -> bytes:
    """
    Serialize a 2D root commitment (affine G1 point) into canonical bytes.

    Parameters:
    - root_commitment: (x, y) pair where x and y may be ints or objects exposing `.n`.
    - compressed: if True, use compressed point format (0x02/0x03 + x), otherwise use uncompressed (0x04 + x + y).
    - include_prefix: whether to include the standard point prefix byte (0x02/0x03/0x04). If False, returns raw coordinate bytes concatenated.
    - field_modulus: optional override for the base field modulus; if None, uses b.field_modulus.

    Returns:
    - bytes: canonical serialization of the point.

    Important:
    - Use the base field modulus (b.field_modulus) to compute coordinate byte-length,
      not b.curve_order. Coordinates are elements of the base field Fq, and their
      size is governed by the field modulus.
    """
    if not (isinstance(root_commitment, (tuple, list)) and len(root_commitment) >= 2):
        raise TypeError("root_commitment must be a 2-tuple (x, y)")

    if field_modulus is None:
        # Coordinates live in the base field; derive length from field_modulus.
        field_modulus = b.field_modulus

    x_obj, y_obj = root_commitment[0], root_commitment[1]
    x_int = _coord_to_int(x_obj)
    y_int = _coord_to_int(y_obj)

    coord_len = (field_modulus.bit_length() + 7) // 8

    x_bytes = _fixed_length_bytes(x_int, coord_len)
    y_bytes = _fixed_length_bytes(y_int, coord_len)

    if not include_prefix:
        return x_bytes + y_bytes

    if compressed:
        # compressed: 0x02 if y is even, 0x03 if y is odd
        prefix = b"\x02" if (y_int % 2 == 0) else b"\x03"
        return prefix + x_bytes

    # uncompressed: 0x04 || X || Y
    return b"\x04" + x_bytes + y_bytes
