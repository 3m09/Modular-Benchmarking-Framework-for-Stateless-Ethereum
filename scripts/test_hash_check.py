# Save this as verify_poseidon.py
from poseidon_py.poseidon_hash import poseidon_hash

# The BN128 Scalar Field Modulus (The "Golden" Prime)
BN128_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def test_hash_consistency():
    # 1. Inputs must match your test_hash.circom inputs (e.g., [1, 2, 3])
    inputs = [1, 2, 3]
    
    # 2. Call the library function
    # Note: Check if your library version requires the modulus as the 2nd arg
    # If it fails with 'takes 1 argument', remove the BN128_PRIME
    try:
        py_result = poseidon_hash(inputs, BN128_PRIME)
    except TypeError:
        py_result = poseidon_hash(inputs)
        
    print(f"Python Poseidon Output (Integer): {py_result}")
    return py_result

if __name__ == "__main__":
    test_hash_consistency()