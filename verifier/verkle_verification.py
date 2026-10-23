# from registry.verifiers import BaseVerifier, register_verifier
# from verkle.randomness_scheme import derive_r, derive_r_factor_hash
# from py_ecc import optimized_bls12_381 as b
# from verkle.hash_scheme import hash_point_to_field
# from verkle.hash_scheme import generate_root_bytes
# from verkle.utils.key_to_path import _key_to_path


# @register_verifier("verkle")
# class VerkleProofVerifier(BaseVerifier):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object

#     def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
#         paths = [_key_to_path(self.setup_object.WIDTH, k) for k in keys]
#         values = [int.from_bytes(v, byteorder='big') for v in values]
#         setup = self.setup_object.setup
#         MODULUS = self.setup_object.MODULUS
#         LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
#         WIDTH = self.setup_object.WIDTH

#         r = derive_r(generate_root_bytes(root), paths, b.curve_order)
#         commitments, witness = proof
#         pairing_check = b.FQ12.one()
#         for (c, key, v, path) in zip(commitments, keys, values, paths):
#            for level, idx in enumerate(path):
#                r_factor = derive_r_factor_hash(generate_root_bytes(root), path, level, b.curve_order)
#                comm = c[level-1] if level > 0 else root
#                comm = (comm[0], comm[1], b.FQ.one())
#                leaf = hash_point_to_field(c[level],MODULUS) if level < len(path) - 1 else v
#                comm_minus_leaf_times_r = b.multiply(b.add(comm, b.multiply(b.G1, MODULUS - leaf)), r_factor)
#                Z_comm = b.multiply(setup[3][idx], self.setup_object.field.inv(LAGRANGE_POLYS[idx][-1]))
#                pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
#         global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
#         # Subtract out sum [Q_i * r_i * Z(everything)]
#         pairing_check *= b.pairing(b.neg(global_Z_comm), (witness[0], witness[1], b.FQ.one()), False)
#         o = b.final_exponentiate(pairing_check)
#         assert o == b.FQ12.one(), o
#         return o == b.FQ12.one()


# from registry.verifiers import BaseVerifier, register_verifier
# from verkle.randomness_scheme import derive_r, derive_r_factor_hash
# from py_ecc import optimized_bls12_381 as b
# from verkle.hash_scheme import hash_point_to_field
# from verkle.hash_scheme import generate_root_bytes
# from verkle.utils.key_to_path import _key_to_path

# @register_verifier("verkle")
# class VerkleProofVerifier(BaseVerifier):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object

#     def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
#         paths_for_r = [_key_to_path(self.setup_object.WIDTH, k) for k in keys]
#         values = [int.from_bytes(v, byteorder='big') for v in values]
#         setup = self.setup_object.setup
#         MODULUS = self.setup_object.MODULUS
#         LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
#         WIDTH = self.setup_object.WIDTH

#         r = derive_r(generate_root_bytes(root), paths_for_r, b.curve_order)
#         commitments, witness = proof
#         pairing_check = b.FQ12.one()
        
#         for (c, key, v, path_for_r) in zip(commitments, keys, values, paths_for_r):
#             stem = key[:31]
#             suffix = key[31]
            
#             # The total number of nodes evaluated in this path
#             L = len(c) + 1
            
#             for level in range(L):
#                 # Dynamically deduce the index based on the EIP-6800 tree structure
#                 if level == L - 1:
#                     idx = suffix        # Bottom level is always Suffix
#                 elif level == L - 2:
#                     idx = 2             # Second to last is always Extension (evaluating child hash at index 2)
#                 else:
#                     idx = stem[level]   # Higher levels are Internals
                    
#                 r_factor = derive_r_factor_hash(generate_root_bytes(root), path_for_r, level, b.curve_order)
#                 comm = c[level-1] if level > 0 else root
#                 comm = (comm[0], comm[1], b.FQ.one())
                
#                 # The expected leaf value (either the intermediate commitment hash or the actual final value)
#                 leaf = hash_point_to_field(c[level], MODULUS) if level < L - 1 else v
                
#                 comm_minus_leaf_times_r = b.multiply(b.add(comm, b.multiply(b.G1, MODULUS - leaf)), r_factor)
#                 Z_comm = b.multiply(setup[3][idx], self.setup_object.field.inv(LAGRANGE_POLYS[idx][-1]))
#                 pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
                
#         global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
        
#         # Subtract out sum [Q_i * r_i * Z(everything)]
#         pairing_check *= b.pairing(b.neg(global_Z_comm), (witness[0], witness[1], b.FQ.one()), False)
#         o = b.final_exponentiate(pairing_check)
        
#         assert o == b.FQ12.one(), "Pairing check failed."
#         return o == b.FQ12.one()

import math
from registry.verifiers import BaseVerifier, register_verifier
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from py_ecc import optimized_bls12_381 as b
from verkle.hash_scheme import hash_point_to_field
from verkle.hash_scheme import generate_root_bytes
from verkle.utils.key_to_path import _key_to_path

@register_verifier("verkle")
class VerkleProofVerifier(BaseVerifier):

    def __init__(self, setup_object):
        self.setup_object = setup_object

    # --- MODIFIED: Added local chunking helper ---
    def _get_key_chunks(self, key_bytes, width):
        bits_per_chunk = int(math.log2(width))
        key_int = int.from_bytes(key_bytes, 'big')
        total_bits = 256
        num_chunks = total_bits // bits_per_chunk
        
        chunks = []
        for i in range(num_chunks):
            shift = total_bits - ((i + 1) * bits_per_chunk)
            mask = width - 1
            chunk = (key_int >> shift) & mask
            chunks.append(chunk)
            
        return tuple(chunks)

    def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
        paths_for_r = [_key_to_path(self.setup_object.WIDTH, k) for k in keys]
        values = [int.from_bytes(v, byteorder='big')  for v in values]
        setup = self.setup_object.setup
        MODULUS = self.setup_object.MODULUS
        LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
        WIDTH = self.setup_object.WIDTH

        r = derive_r(generate_root_bytes(root), paths_for_r, b.curve_order)
        commitments, witness = proof
        pairing_check = b.FQ12.one()
        
        for (c, key, v, path_for_r) in zip(commitments, keys, values, paths_for_r):
            # --- MODIFIED: Use dynamic chunking instead of [31] splits ---
            chunks = self._get_key_chunks(key, WIDTH)
            stem = chunks[:-1]
            suffix = chunks[-1]
            
            L = len(c) + 1
            
            for level in range(L):
                if level == L - 1:
                    idx = suffix       
                elif level == L - 2:
                    idx = 2            
                else:
                    idx = stem[level]   
                    
                r_factor = derive_r_factor_hash(generate_root_bytes(root), path_for_r, level, b.curve_order)
                comm = c[level-1] if level > 0 else root
                comm = (comm[0], comm[1], b.FQ.one())
                
                leaf = hash_point_to_field(c[level], MODULUS) if level < L - 1 else v

                # # Properly modulo the negated leaf so it is always a valid positive scalar
                # neg_leaf_scalar = (-leaf) % b.curve_order
                                
                # comm_minus_leaf_times_r = b.multiply(b.add(comm, b.multiply(b.G1, neg_leaf_scalar)), r_factor)
                
                comm_minus_leaf_times_r = b.multiply(b.add(comm, b.multiply(b.G1, MODULUS - leaf)), r_factor)
                Z_comm = b.multiply(setup[3][idx], self.setup_object.field.inv(LAGRANGE_POLYS[idx][-1]))
                pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
                
        global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
        
        pairing_check *= b.pairing(b.neg(global_Z_comm), (witness[0], witness[1], b.FQ.one()), False)
        o = b.final_exponentiate(pairing_check)
        
        assert o == b.FQ12.one(), "Pairing check failed."
        return o == b.FQ12.one()