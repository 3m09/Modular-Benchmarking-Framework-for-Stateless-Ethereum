# from registry.verifiers import BaseVerifier, register_verifier
# from verkle.randomness_scheme import derive_r
# from py_ecc import optimized_bls12_381 as b
# from verkle.hash_scheme import generate_root_bytes
# from verkle.hash_scheme import hash_point_to_field


# @register_verifier("verkle_multiproof")
# class VerkleMultiproofVerifier(BaseVerifier):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object

#     def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
#         proof_dict, witness_raw = proof
        
#         setup = self.setup_object.setup
#         MODULUS = self.setup_object.MODULUS
#         LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
#         WIDTH = self.setup_object.WIDTH
#         field = self.setup_object.field
        
#         commitments_with_openings = proof_dict['commitments_with_openings']
#         key_paths = proof_dict['key_paths']
#         root_commitment = proof_dict['root_commitment']
#         witness_tuple = proof_dict['witness']
        
#         root = (b.FQ(root_commitment[0]), b.FQ(root_commitment[1]))
#         r = derive_r(generate_root_bytes(root), key_paths, b.curve_order)
        
#         print(f"DEBUG: r = {r}")
#         print(f"DEBUG: Number of nodes = {len(commitments_with_openings)}")
        
#         pairing_check = b.FQ12.one()
#         r_power = 1
#         opening_count = 0
        
#         for node_data in commitments_with_openings:
#             commitment = node_data['commitment']
#             openings = node_data['openings']
            
#             comm_point = (b.FQ(commitment[0]), b.FQ(commitment[1]), b.FQ.one())
            
#             sorted_openings = sorted(openings.items(), key=lambda x: int(x[0]))
            
#             for idx, leaf_value in sorted_openings:
#                 idx = int(idx)
#                 opening_count += 1
                
#                 neg_leaf_times_g1 = b.multiply(b.G1, (MODULUS - leaf_value) % MODULUS)
#                 comm_minus_leaf = b.add(comm_point, neg_leaf_times_g1)
#                 comm_minus_leaf_times_r = b.multiply(comm_minus_leaf, r_power)
                
#                 lagrange_inv = field.inv(LAGRANGE_POLYS[idx][-1])
#                 Z_comm = b.multiply(setup[3][idx], lagrange_inv)
                
#                 pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
                
#                 r_power = (r_power * r) % b.curve_order
        
#         print(f"DEBUG: Total openings processed = {opening_count}")
        
#         global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
#         witness_point = (b.FQ(witness_tuple[0]), b.FQ(witness_tuple[1]), b.FQ.one())
        
#         pairing_check *= b.pairing(b.neg(global_Z_comm), witness_point, False)
        
#         result = b.final_exponentiate(pairing_check)
        
#         if result != b.FQ12.one():
#             print(f"Multiproof verification failed!")
#             return False
        
#         print("Multiproof verification PASSED!")
#         return True

#     # def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
#     #     proof_dict, witness_raw = proof
        
#     #     setup = self.setup_object.setup
#     #     MODULUS = self.setup_object.MODULUS
#     #     LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
#     #     WIDTH = self.setup_object.WIDTH
#     #     field = self.setup_object.field
        
#     #     commitments_with_openings = proof_dict['commitments_with_openings']
#     #     key_paths = proof_dict['key_paths']
#     #     root_commitment = proof_dict['root_commitment']
#     #     witness_tuple = proof_dict['witness']
        
#     #     root_point = (b.FQ(root_commitment[0]), b.FQ(root_commitment[1]))
#     #     r = derive_r(generate_root_bytes(root_point), key_paths, b.curve_order)
        
#     #     print(f"DEBUG: r = {r}")
#     #     print(f"DEBUG: Number of nodes = {len(commitments_with_openings)}")
        
#     #     # =====================================================================
#     #     # NEW STEP 1: Topological Mapping (Trading Bandwidth for Compute)
#     #     # We reconstruct the parent-child relationships using the paths so we 
#     #     # can calculate intermediate node openings dynamically via hashing.
#     #     # =====================================================================
        
#     #     # Build a quick lookup dictionary of all commitments by their level
#     #     # so we can easily find child commitments.
#     #     comms_by_level = {}
#     #     for node in commitments_with_openings:
#     #         lvl = node['level']
#     #         if lvl not in comms_by_level:
#     #             comms_by_level[lvl] = []
#     #         comms_by_level[lvl].append(node['commitment'])
            
#     #     # We will build our own calculated openings map: (commitment, idx) -> value
#     #     calculated_openings = {}
        
#     #     for key_idx, path in enumerate(key_paths):
#     #         current_comm = root_commitment
            
#     #         for level in range(len(path)):
#     #             idx = path[level]
                
#     #             if level < len(path) - 1:
#     #                 # INTERMEDIATE NODE: The opening is the hash of the child's commitment.
#     #                 # We find the child commitment from our topology map.
#     #                 # (In a highly optimized production verifier, the commitments are 
#     #                 # passed in a strictly flattened topological order to avoid lookups).
#     #                 child_comm = comms_by_level[level + 1][0] # Simplified lookup
                    
#     #                 # Compute the opening on the fly!
#     #                 opening_value = hash_point_to_field(child_comm, MODULUS)
#     #                 calculated_openings[(current_comm, idx)] = opening_value
                    
#     #                 current_comm = child_comm
#     #             else:
#     #                 # LEAF NODE: The verifier cannot guess state data.
#     #                 # This is the ONLY time we read from the actual payload values.
#     #                 leaf_value = int.from_bytes(values[key_idx], byteorder='big')
#     #                 calculated_openings[(current_comm, idx)] = leaf_value

#     #     # =====================================================================
#     #     # STEP 2: The standard pairing check loop
#     #     # Notice we are no longer reading `openings` from `node_data`!
#     #     # =====================================================================
        
#     #     pairing_check = b.FQ12.one()
#     #     r_power = 1
#     #     opening_count = 0
        
#     #     for node_data in commitments_with_openings:
#     #         commitment = node_data['commitment']
#     #         # We completely ignore node_data['openings'] here to simulate bandwidth savings!
            
#     #         comm_point = (b.FQ(commitment[0]), b.FQ(commitment[1]), b.FQ.one())
            
#     #         # Find all calculated openings that belong to this specific commitment
#     #         node_openings = {idx: val for (comm, idx), val in calculated_openings.items() if comm == commitment}
#     #         sorted_openings = sorted(node_openings.items(), key=lambda x: int(x[0]))
            
#     #         for idx, leaf_value in sorted_openings:
#     #             idx = int(idx)
#     #             opening_count += 1
                
#     #             # --- The cryptographic check remains identical ---
#     #             neg_leaf_times_g1 = b.multiply(b.G1, (MODULUS - leaf_value) % MODULUS)
#     #             comm_minus_leaf = b.add(comm_point, neg_leaf_times_g1)
#     #             comm_minus_leaf_times_r = b.multiply(comm_minus_leaf, r_power)
                
#     #             lagrange_inv = field.inv(LAGRANGE_POLYS[idx][-1])
#     #             Z_comm = b.multiply(setup[3][idx], lagrange_inv)
                
#     #             pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
                
#     #             r_power = (r_power * r) % b.curve_order
        
#     #     print(f"DEBUG: Total openings calculated dynamically = {opening_count}")
        
#     #     global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
#     #     witness_point = (b.FQ(witness_tuple[0]), b.FQ(witness_tuple[1]), b.FQ.one())
        
#     #     pairing_check *= b.pairing(b.neg(global_Z_comm), witness_point, False)
        
#     #     result = b.final_exponentiate(pairing_check)
        
#     #     if result != b.FQ12.one():
#     #         print(f"Multiproof verification failed!")
#     #         return False
        
#     #     print("Multiproof verification PASSED!")
#     #     return True


from registry.verifiers import BaseVerifier, register_verifier
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from py_ecc import optimized_bls12_381 as b
from verkle.hash_scheme import generate_root_bytes, hash_point_to_field
from verkle.utils.key_to_path import _key_to_path

@register_verifier("verkle_multiproof")
class VerkleMultiproofVerifier(BaseVerifier):

    def __init__(self, setup_object):
        self.setup_object = setup_object

    # def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
    #     proof_dict, witness_tuple = proof
    #     commitments_flat = proof_dict.get('commitments', [])
        
    #     setup = self.setup_object.setup
    #     MODULUS = self.setup_object.MODULUS
    #     LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
    #     WIDTH = self.setup_object.WIDTH
    #     field = self.setup_object.field
        
    #     paths_for_r = [_key_to_path(WIDTH, k) for k in keys]
    #     values = [int.from_bytes(v, byteorder='big') for v in values]
    #     r = derive_r(generate_root_bytes(root), paths_for_r, b.curve_order)
        
    #     print(f"DEBUG VERIFIER: r={r}")
        
    #     pairing_check = b.FQ12.one()
        
    #     for key_idx, (key, value, path_for_r) in enumerate(zip(keys, values, paths_for_r)):
    #         stem = key[:31]
    #         suffix = key[31]
    #         current_comm = root 
    #         L = 3 
            
    #         for level in range(L):
    #             idx = suffix if level == L - 1 else (2 if level == L - 2 else stem[level])
    #             r_factor = derive_r_factor_hash(generate_root_bytes(root), path_for_r, level, b.curve_order)
                
    #             # Dynamic Commitment Fetching
    #             if level < L - 1:
    #                 comm_idx = key_idx * (L - 1) + level
    #                 next_comm_tuple = commitments_flat[comm_idx]
    #                 next_comm = (b.FQ(next_comm_tuple[0]), b.FQ(next_comm_tuple[1]))
    #                 leaf = hash_point_to_field(next_comm, MODULUS)
    #             else:
    #                 leaf = value
                
    #             # --- DEBUG LOGGING ---
    #             comm_point = (current_comm[0], current_comm[1], b.FQ.one())
    #             print(f"DEBUG VERIFIER [Key {key_idx}, Level {level}]:")
    #             print(f"  idx: {idx}")
    #             print(f"  leaf: {hex(leaf)}")
    #             print(f"  r_factor: {r_factor}")
    #             print(f"  comm_point (x): {hex(int(comm_point[0]))}")
                
    #             neg_leaf_times_g1 = b.multiply(b.G1, (MODULUS - leaf) % MODULUS)
    #             comm_minus_leaf = b.add(comm_point, neg_leaf_times_g1)
    #             comm_minus_leaf_times_r = b.multiply(comm_minus_leaf, r_factor)
                
    #             Z_comm = b.multiply(setup[3][idx], field.inv(LAGRANGE_POLYS[idx][-1]))
    #             p = b.pairing(Z_comm, comm_minus_leaf_times_r, False)
                
    #             if p == b.FQ12.one():
    #                 print(f"  Status: Pairing Success at Level {level}")
    #             else:
    #                 print(f"  Status: PAIRING FAILED at Level {level}")
                
    #             pairing_check *= p
    #             current_comm = next_comm if level < L - 1 else None

    #     # Witness Check
    #     global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
    #     witness_point = (b.FQ(witness_tuple[0]), b.FQ(witness_tuple[1]), b.FQ.one())
    #     w_p = b.pairing(b.neg(global_Z_comm), witness_point, False)
        
    #     print(f"DEBUG VERIFIER: Witness Pairing: {w_p == b.FQ12.one()}")
    #     pairing_check *= w_p
        
    #     result = b.final_exponentiate(pairing_check)
    #     return result == b.FQ12.one()

    # def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
    #     proof_dict, witness_tuple = proof
    #     commitments_flat = proof_dict.get('commitments', [])
        
    #     setup = self.setup_object.setup
    #     MODULUS = self.setup_object.MODULUS
    #     LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
    #     WIDTH = self.setup_object.WIDTH
    #     field = self.setup_object.field
        
    #     paths_for_r = [_key_to_path(WIDTH, k) for k in keys]
    #     values = [int.from_bytes(v, byteorder='big') for v in values]
    #     r = derive_r(generate_root_bytes(root), paths_for_r, b.curve_order)
        
    #     pairing_check = b.FQ12.one()
        
    #     for key_idx, (key, value, path_for_r) in enumerate(zip(keys, values, paths_for_r)):
    #         stem = key[:31]
    #         suffix = key[31]
            
    #         # current_comm tracks the node being opened
    #         current_comm = root
    #         L = 3 
            
    #         for level in range(L):
    #             # 1. Selection of idx based on EIP-6800 hierarchy
    #             if level == L - 1:
    #                 idx = suffix
    #             elif level == L - 2:
    #                 idx = 2
    #             else:
    #                 idx = stem[level]
                
    #             # 2. Derive r_factor for the current level
    #             r_factor = derive_r_factor_hash(generate_root_bytes(root), path_for_r, level, b.curve_order)
                
    #             # 3. Dynamic lookup of child commitment and leaf calculation
    #             if level < L - 1:
    #                 comm_idx = key_idx * (L - 1) + level
    #                 next_comm_tuple = commitments_flat[comm_idx]
    #                 # Explicit FQ conversion ensures py_ecc field compatibility
    #                 next_comm = (b.FQ(next_comm_tuple[0]), b.FQ(next_comm_tuple[1]))
    #                 leaf = hash_point_to_field(next_comm, MODULUS)
    #             else:
    #                 next_comm = None
    #                 leaf = value
                
    #             # 4. Canonical Point Normalization (Affine coordinates)
    #             x = b.FQ(current_comm[0])
    #             y = b.FQ(current_comm[1])
    #             comm_point = (x, y, b.FQ.one())
                
    #             neg_leaf_times_g1 = b.multiply(b.G1, (MODULUS - leaf) % MODULUS)
    #             comm_minus_leaf = b.add(comm_point, neg_leaf_times_g1)
    #             comm_minus_leaf_times_r = b.multiply(comm_minus_leaf, r_factor)
                
    #             # 5. Pairing Accumulation
    #             Z_comm = b.multiply(setup[3][idx], field.inv(LAGRANGE_POLYS[idx][-1]))
    #             pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
                
    #             # Move to child commitment for next iteration
    #             current_comm = next_comm if level < L - 1 else None

    #     # 6. Final Witness Check
    #     global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
    #     witness_point = (b.FQ(witness_tuple[0]), b.FQ(witness_tuple[1]), b.FQ.one())
        
    #     pairing_check *= b.pairing(b.neg(global_Z_comm), witness_point, False)
        
    #     result = b.final_exponentiate(pairing_check)
    #     return result == b.FQ12.one()
    def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
        proof_dict, witness_tuple = proof
        key_traversals = proof_dict.get('key_traversals', {})

        setup = self.setup_object.setup
        LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
        WIDTH = self.setup_object.WIDTH
        field = self.setup_object.field

        paths_for_r = [_key_to_path(WIDTH, k) for k in keys]
        values_int = [int.from_bytes(v, byteorder='big') for v in values]

        pairing_check = b.FQ12.one()

        for key_idx, (value, path_for_r) in enumerate(zip(values_int, paths_for_r)):
            traversal = key_traversals[key_idx]

            for depth, (comm_tuple, idx, node_type, child_val) in enumerate(traversal):
                # Fix 3: idx comes directly from traversal, not a level-position formula
                # Fix 4: leaf comes from child_val (raw int.from_bytes), not hash_point_to_field
                if node_type == 'suffix':
                    leaf = value
                else:
                    leaf = child_val

                # Fix 1: depth drives r_factor, not a hardcoded L
                r_factor = derive_r_factor_hash(
                    generate_root_bytes(root), path_for_r, depth, b.curve_order
                )

                x = b.FQ(comm_tuple[0])
                y = b.FQ(comm_tuple[1])
                comm_point = (x, y, b.FQ.one())

                MODULUS = b.curve_order
                neg_leaf_times_g1 = b.multiply(b.G1, (MODULUS - leaf) % MODULUS)
                comm_minus_leaf = b.add(comm_point, neg_leaf_times_g1)
                comm_minus_leaf_times_r = b.multiply(comm_minus_leaf, r_factor)

                Z_comm = b.multiply(setup[3][idx], field.inv(LAGRANGE_POLYS[idx][-1]))
                pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)

        # Final Witness Check
        global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
        witness_point = (b.FQ(witness_tuple[0]), b.FQ(witness_tuple[1]), b.FQ.one())

        pairing_check *= b.pairing(b.neg(global_Z_comm), witness_point, False)

        result = b.final_exponentiate(pairing_check)
        return result == b.FQ12.one()