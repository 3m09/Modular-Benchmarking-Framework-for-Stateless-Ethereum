from py_ecc import optimized_bls12_381 as b
from .utils.fft import fft
from .utils.multicombs import lincomb
from .utils.poly_utils import PrimeField

def commit_extension(stem_bytes, child_commitment_bytes, setup_object):
    """
    EIP-6800 compliant Extension Node commitment.
    Commits to: [Node_Type, Stem_Integer, Child_Commitment, 0]
    """
    MODULUS = setup_object.MODULUS
    ROOT_OF_UNITY = setup_object.ROOT_OF_UNITY
    
    # 1. Node type for Extension is 1
    val_type = 1 
    
    # 2. Treat the 31-byte stem as a single integer
    val_stem = int.from_bytes(stem_bytes, byteorder='big')
    
    # 3. The child commitment
    val_child = int.from_bytes(child_commitment_bytes, byteorder='big') if child_commitment_bytes else 0
    
    # We pad to 4 or 8 depending on your FFT implementation requirements
    # Assuming your FFT can handle a width of 4:
    values = [val_type, val_stem, val_child, 0]
    
    # Pad to your setup's required WIDTH (if your FFT strictly requires 256)
    # values += [0] * (setup_object.WIDTH - len(values))
    
    coeffs = fft(values, MODULUS, ROOT_OF_UNITY, inv=True)
    
    return b.normalize(lincomb(setup_object.setup[0][:len(coeffs)], coeffs, b.add, b.Z1))

def commit(values, setup_object):
    MODULUS = setup_object.MODULUS
    WIDTH = setup_object.WIDTH
    ROOT_OF_UNITY = setup_object.ROOT_OF_UNITY
    values += [0] * (WIDTH - len(values))
    coeffs = fft(values, MODULUS, ROOT_OF_UNITY, inv=True)
    
    return b.normalize(lincomb(setup_object.setup[0][:len(coeffs)], coeffs, b.add, b.Z1))

def generate_quotient(values, index, setup_object):
    MODULUS = setup_object.MODULUS
    WIDTH = setup_object.WIDTH
    POWERS = setup_object.POWERS
    INVERSES = setup_object.INVERSES
    LAGRANGE_POLYS = setup_object.LAGRANGE_POLYS

    field = PrimeField(MODULUS)

    #x = pow(ROOT_OF_UNITY, index, MODULUS)
    P = [field.sub(v, values[index]) for v in values]
    P[index] = 0
    inv_Q = INVERSES[index]
    P_over_Q = [field.mul(a,b) for a,b in zip(P, inv_Q)]
    top_coeff = field.div(sum([field.mul(a, p) for a, p in zip(P_over_Q, POWERS)]), WIDTH)
    lagrange_coefficient = field.div(top_coeff, LAGRANGE_POLYS[index][-1])
    P_over_Q[index] = MODULUS - lagrange_coefficient
    #P_over_Q_coeffs = fft(P_over_Q, MODULUS, ROOT_OF_UNITY, inv=True)
    #assert P_over_Q_coeffs[-1] == 0
    #assert fft(field.mul_polys(P_over_Q_coeffs[:-1], [-x, 1]), MODULUS, ROOT_OF_UNITY) == P
    return P_over_Q