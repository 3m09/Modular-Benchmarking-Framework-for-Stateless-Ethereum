# from Crypto.Hash import keccak

# # Import your custom, constraint-free Poseidon implementation
# from zkSNARK.myposeidonhash import poseidon_hash

# FIELD_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513

# def keccak_hash(data):
#     keccak_hash = keccak.new(digest_bits=256)
#     keccak_hash.update(data)
#     return keccak_hash.digest()

# def poseidon_hash_bytes(data: bytes) -> bytes:
#     """
#     Sequential ZK Sponge Hash (t=2 arity).
#     Uses the custom pure-Python myposeidonhash to guarantee exact matrix matching 
#     without triggering PySnark's constraint writer.
#     """
#     # 1. Pad to exact 32-byte alignment
#     remainder = len(data) % 32
#     if remainder != 0:
#         data += b'\0' * (32 - remainder)

#     # 2. Slice into 32-byte chunks
#     chunks = [data[i:i+32] for i in range(0, len(data), 32)]
#     field_elements = [int.from_bytes(chunk, "big") % FIELD_MOD for chunk in chunks]

#     # 3. Execute the pure Python sponge loop
#     current_hash = 0
    
#     for element in field_elements:
#         # Modulo the addition to prevent field overflow
#         combined = (current_hash + element) % FIELD_MOD
        
#         # Call your custom pure-Python hash function. 
#         # It takes a list of integers and the modulus.
#         hash_result = poseidon_hash([combined], FIELD_MOD) 
        
#         # The result is a list of integers, extract the first one
#         current_hash = hash_result[0]

#     return current_hash.to_bytes(32, "big")

# from Crypto.Hash import keccak

# # Import your custom, constraint-free Poseidon implementation
# from zkSNARK.myposeidonhash import poseidon_hash

# FIELD_MOD = 52435875175126190479447740508185965837690552500527637822603658699938581184513
# BATCH_SIZE = 4  # Optimized Arity

# def keccak_hash(data):
#     keccak_hash = keccak.new(digest_bits=256)
#     keccak_hash.update(data)
#     return keccak_hash.digest()

# def poseidon_hash_bytes(data: bytes) -> bytes:
#     """
#     Batched ZK Sponge Hash.
#     Processes multiple field elements per permutation to massively reduce overhead.
#     """
#     # 1. Pad to exact 32-byte alignment
#     remainder = len(data) % 32
#     if remainder != 0:
#         data += b'\0' * (32 - remainder)

#     # 2. Slice into 32-byte chunks
#     chunks = [data[i:i+32] for i in range(0, len(data), 32)]
#     field_elements = [int.from_bytes(chunk, "big") % FIELD_MOD for chunk in chunks]

#     # 3. Execute the Batched Python sponge loop
#     current_hash = 0
    
#     for i in range(0, len(field_elements), BATCH_SIZE):
#         batch = field_elements[i:i+BATCH_SIZE]
        
#         # Pad batch to exact BATCH_SIZE to ensure constant arity
#         while len(batch) < BATCH_SIZE:
#             batch.append(0)
            
#         # Modulo the addition to prevent field overflow
#         batch[0] = (current_hash + batch[0]) % FIELD_MOD
        
#         # Execute permutation on the entire batch
#         hash_result = poseidon_hash(batch, FIELD_MOD) 
#         current_hash = hash_result[0]

#     return current_hash.to_bytes(32, "big")

# from Crypto.Hash import keccak
# # REPLACE YOUR LOCAL IMPORT WITH THE LIBRARY IMPORT
# from poseidon_py.poseidon_hash import poseidon_hash 

# # Update this to the BN128 prime for circom compatibility
# FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
# BATCH_SIZE = 4 

# def keccak_hash(data):
#     keccak_hash = keccak.new(digest_bits=256)
#     keccak_hash.update(data)
#     return keccak_hash.digest()

# def poseidon_hash_bytes(data: bytes) -> bytes:
#     """
#     Batched Sponge Hash using the circom-compatible poseidon-py library.
#     """
#     # 1. Pad to 32-byte alignment
#     remainder = len(data) % 32
#     if remainder != 0:
#         data += b'\0' * (32 - remainder)

#     # 2. Slice into 32-byte chunks
#     chunks = [data[i:i+32] for i in range(0, len(data), 32)]
#     field_elements = [int.from_bytes(chunk, "big") % FIELD_MOD for chunk in chunks]

#     # 3. Execute the sponge loop
#     current_hash = 0
    
#     for i in range(0, len(field_elements), BATCH_SIZE):
#         batch = field_elements[i:i+BATCH_SIZE]
        
#         # Pad batch to exact BATCH_SIZE (Arity)
#         while len(batch) < BATCH_SIZE:
#             batch.append(0)
            
#         # Mix the current state (current_hash) into the first element of the batch
#         batch[0] = (current_hash + batch[0]) % FIELD_MOD
        
#         # Call the library function directly
#         # poseidon-py handles the MDS matrix and Round Constants internally
#         current_hash = poseidon_hash(batch) 

#     return current_hash.to_bytes(32, "big")

import subprocess
import json
from Crypto.Hash import keccak
import os

FIELD_MOD = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BATCH_SIZE = 4

# ── Persistent Node.js worker ────────────────────────────────────────────────
class CircomPoseidon:
    """
    Wraps a persistent circomlibjs Node process.
    One process, many hash calls — no per-call startup overhead.
    """

    def __init__(self):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        worker_path = os.path.join(script_dir, "poseidon_worker.js")
        
        self._proc = subprocess.Popen(
            ["node", worker_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            cwd=script_dir,   # also set cwd so node can find node_modules
        )

    def hash(self, inputs: list[int]) -> list[int]:
        """
        Drop-in replacement for poseidon_hash(batch, FIELD_MOD).
        Takes a list of ints, returns [hash_output] to match your existing
        `hash_result[0]` access pattern.
        """
        # circomlibjs accepts plain numbers but large ints need string encoding
        line = json.dumps([str(x) for x in inputs]) + "\n"
        self._proc.stdin.write(line)
        self._proc.stdin.flush()
        result = int(self._proc.stdout.readline().strip())
        return [result]   # wrapped in list so hash_result[0] still works

    def close(self):
        self._proc.stdin.close()
        self._proc.wait()

# Instantiate once at module level
_poseidon = CircomPoseidon()

# ── Only this function changes — everything else in your code stays identical ─
def poseidon_hash(inputs: list[int], modulus: int) -> list[int]:
    """
    Replaces your myposeidonhash.poseidon_hash with circomlib-exact output.
    Same signature: takes list of ints + modulus, returns [result].
    """
    return _poseidon.hash(inputs)


# ── Your original functions — completely unchanged ───────────────────────────
def keccak_hash(data):
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def poseidon_hash_bytes(data: bytes) -> bytes:
    remainder = len(data) % 32
    if remainder != 0:
        data += b'\0' * (32 - remainder)

    chunks = [data[i:i+32] for i in range(0, len(data), 32)]
    field_elements = [int.from_bytes(chunk, "big") % FIELD_MOD for chunk in chunks]

    current_hash = 0
    for i in range(0, len(field_elements), BATCH_SIZE):
        batch = field_elements[i:i+BATCH_SIZE]
        while len(batch) < BATCH_SIZE:
            batch.append(0)
        batch[0] = (current_hash + batch[0]) % FIELD_MOD

        hash_result = poseidon_hash(batch, FIELD_MOD)  # <-- now calls circomlib
        current_hash = hash_result[0]

    return current_hash.to_bytes(32, "big")