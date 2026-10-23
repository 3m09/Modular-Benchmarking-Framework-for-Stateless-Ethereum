import os
from pysnark.runtime import PrivVal
from pysnark.poseidon_hash import poseidon_hash
import poseidon

# Set backend just like the prover script
# os.environ["PYSNARK_BACKEND"] = "zkifbellman"

FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617

# 1. Initialize the External Library (Your tree builder)
poseidon_hasher = poseidon.Poseidon(
    p=FIELD_MOD, 
    security_level=128, 
    alpha=5, 
    input_rate=1, 
    t=2
)

def test_matrices():
    # A simple, raw integer. No bytes, no padding, no chunking.
    test_number = 12345
    print(f"Testing raw input: {test_number}\n")

    # 2. Hash using the External Library
    ext_result = poseidon_hasher.run_hash([test_number])
    ext_hash = int(ext_result)
    print(f"External Library Hash: {ext_hash}")

    # 3. Hash using the Internal pysnark Circuit
    int_result = poseidon_hash([PrivVal(test_number)])
    int_hash = int_result[0].value
    print(f"pysnark Circuit Hash:  {int_hash}\n")

    # 4. The Verdict
    if ext_hash == int_hash:
        print("VERDICT: The matrices MATCH. The hypothesis is wrong, and the bug is elsewhere.")
    else:
        print("VERDICT: The matrices DO NOT MATCH. The libraries use different domain separation/padding. The hypothesis is correct.")

if __name__ == "__main__":
    test_matrices()