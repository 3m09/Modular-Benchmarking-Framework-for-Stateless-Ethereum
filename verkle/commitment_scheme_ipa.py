from py_ecc import optimized_bls12_381 as b
from .utils.multicombs import lincomb

def commit(values, setup_object, blinding=0):
    """
    IPA-style vector commitment:
      C = <values, G> + blinding * H

    values: list[int]
    setup_object: IPASetup (must provide WIDTH, MODULUS, G, H)
    """
    WIDTH = setup_object.WIDTH
    MODULUS = setup_object.MODULUS

    # pad to WIDTH
    values = list(values) + [0] * (WIDTH - len(values))

    # reduce to scalar field
    scalars = [int(v) % MODULUS for v in values]

    C = lincomb(setup_object.G[:len(scalars)], scalars, b.add, b.Z1)

    if blinding % MODULUS != 0:
        C = b.add(C, b.multiply(setup_object.H, blinding % MODULUS))

    return b.normalize(C)