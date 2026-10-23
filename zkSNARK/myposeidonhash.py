import os
from pysnark.poseidon_constants import poseidon_constants

"""
Constraint-Free Python implementation of the Poseidon hash function.
Evaluates the hash natively over standard integers.
"""

# Load Poseidon parameters
# try:
#     backend = os.environ.get("PYSNARK_BACKEND", "nobackend")
# except KeyError:
#     backend = "nobackend"
backend = "zkifbellman"  

if backend in poseidon_constants:
    constants = poseidon_constants[backend]
else:
    raise NotImplementedError("Poseidon is currently not implemented for this backend")

R_F = constants["R_F"]
R_P = constants["R_P"]
t = constants["t"]
a = constants["a"]
round_constants = constants["round_constants"]
matrix = constants["matrix"]


def matmul(x, y, modulus):
    assert(len(x[0]) == len(y))

    result = [[0 for _ in range(len(y[0]))] for _ in range(len(x))]

    for i in range(len(x)):
        for j in range(len(y[0])):
            for k in range(len(y)):
                result[i][j] = (result[i][j] + x[i][k] * y[k][j]) % modulus

    return result


def transpose(inputs):
    result = [[None for _ in range(len(inputs))] for _ in range(len(inputs[0]))]

    for i in range(len(inputs)):
        for j in range(len(inputs[0])):
            result[j][i] = inputs[i][j]

    return result


def permute(sponge, modulus):
    """
    Runs the Poseidon permutation over native integers.
    """
    # First full rounds
    for r in range(R_F // 2):
        # Add round constants
        sponge = [(x + y) % modulus for (x, y) in zip(sponge, round_constants[r])]
        # Full S-box layer
        sponge = [pow(x, a, modulus) for x in sponge]
        # Mix layer
        sponge = transpose(matmul(matrix, transpose([sponge]), modulus))[0]

    # Partial rounds
    for r in range(R_P):
        # Add round constants
        sponge = [(x + y) % modulus for (x, y) in zip(sponge, round_constants[R_F // 2 + r])]
        # Partial S-box layer
        sponge[0] = pow(sponge[0], a, modulus)
        # Mix layer
        sponge = transpose(matmul(matrix, transpose([sponge]), modulus))[0]

    # Final full rounds
    for r in range(R_F // 2):
        # Add round constants
        sponge = [(x + y) % modulus for (x, y) in zip(sponge, round_constants[R_F // 2 + R_P + r])]
        # Full S-box layer
        sponge = [pow(x, a, modulus) for x in sponge]
        # Mix layer
        sponge = transpose(matmul(matrix, transpose([sponge]), modulus))[0]

    return sponge


def poseidon_hash(inputs, modulus):
    """
    Runs the Poseidon hash on a list of standard integers.
    
    :param inputs: A list of integers to hash.
    :param modulus: The prime modulus of your specific curve.
    """
    if not isinstance(inputs, list):
        raise RuntimeError("Can only hash lists of integers")
    if not all(isinstance(x, int) for x in inputs):
        raise RuntimeError("Inputs must be standard integers")

    # Pad inputs
    inputs_per_round = t - 1
    num_pad = inputs_per_round - len(inputs) % inputs_per_round
    num_zeros = num_pad - 1
    
    # Pad with 1 and 0s instead of LinComb representations
    inputs = inputs + [1] + [0] * num_zeros
    assert len(inputs) % inputs_per_round == 0

    # Run hash
    sponge = [0] * t
    hash_rounds = len(inputs) // inputs_per_round

    for i in range(hash_rounds):
        # Add inputs
        round_inputs = inputs[i * inputs_per_round: (i + 1) * inputs_per_round]
        sponge[1:] = [(s + b) % modulus for (s, b) in zip(sponge[1:], round_inputs)]

        # Run permutation
        sponge = permute(sponge, modulus)

    return sponge[1:]