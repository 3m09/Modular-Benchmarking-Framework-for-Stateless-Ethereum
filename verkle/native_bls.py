"""
Native BLS12-381 arithmetic for the Verkle/KZG backend, via blst (pyblst).

The tree, the transcript and the proof layout are unchanged; only the group
operations of proving and verification move from pure-Python py_ecc to blst.

Points are exchanged in the ZCash/IETF compressed encoding (48 bytes for G1,
96 bytes for G2). `uncompress` performs the on-curve and subgroup checks a
verifier needs for every point it receives.
"""
import pyblst
from py_ecc import optimized_bls12_381 as b

P = b.field_modulus
_HALF = (P - 1) // 2
_COMPRESSED, _INFINITY, _SIGN = 0x80, 0x40, 0x20

G1_IDENTITY = pyblst.BlstP1Element()


def g1_compress(point) -> bytes:
    """py_ecc affine G1 point (x, y) or None (infinity) -> 48-byte compressed encoding."""
    if point is None:
        return bytes([_COMPRESSED | _INFINITY]) + bytes(47)
    x, y = int(point[0].n if hasattr(point[0], "n") else point[0]), int(point[1].n if hasattr(point[1], "n") else point[1])
    out = bytearray(x.to_bytes(48, "big"))
    out[0] |= _COMPRESSED | (_SIGN if y > _HALF else 0)
    return bytes(out)


def g2_compress(point) -> bytes:
    """py_ecc affine G2 point -> 96-byte compressed encoding (imaginary part first)."""
    x0, x1 = (int(c) for c in point[0].coeffs)
    y0, y1 = (int(c) for c in point[1].coeffs)
    largest = (y1 > _HALF) if y1 else (y0 > _HALF)
    out = bytearray(x1.to_bytes(48, "big") + x0.to_bytes(48, "big"))
    out[0] |= _COMPRESSED | (_SIGN if largest else 0)
    return bytes(out)


def g1_uncompress(data: bytes):
    return pyblst.BlstP1Element().uncompress(data)


def g2_uncompress(data: bytes):
    return pyblst.BlstP2Element().uncompress(data)


def g1_from_pyecc(point):
    if len(point) == 3:          # projective
        point = b.normalize(point)
    return g1_uncompress(g1_compress(point))


def g2_from_pyecc(point):
    if len(point) == 3:
        point = b.normalize(point)
    return pyblst.BlstP2Element().uncompress(g2_compress(point))


def msm(points, scalars):
    """sum(s_i * P_i) over the non-zero scalars."""
    acc = pyblst.BlstP1Element()
    for pt, s in zip(points, scalars):
        if s:
            acc = acc + pt.scalar_mul(s)
    return acc


def native_setup(setup_object):
    """Setup points converted once to blst and cached on the setup object (setup data, not proof data)."""
    cached = getattr(setup_object, "_native", None)
    if cached is None:
        g1_monomial, g2_monomial, g1_lagrange, g2_lagrange = setup_object.setup
        cached = {
            "G1": g1_from_pyecc(b.G1),
            "g1_lagrange": [g1_from_pyecc(p) for p in g1_lagrange],
            "g2_lagrange": [g2_from_pyecc(p) for p in g2_lagrange],
            "g2_s_W": g2_from_pyecc(g2_monomial[setup_object.WIDTH]),
            "g2_one": g2_from_pyecc(g2_monomial[0]),
        }
        setup_object._native = cached
    return cached


def pairing_product_equals(lhs_pairs, rhs_pair) -> bool:
    """prod e(P_i, Q_i) == e(P, Q), checked with one final exponentiation."""
    acc = None
    for p1, p2 in lhs_pairs:
        ml = pyblst.miller_loop(p1, p2)
        acc = ml if acc is None else acc * ml
    return pyblst.final_verify(acc, pyblst.miller_loop(*rhs_pair))
