# from registry.provers import BaseProver, register_prover
# from tree.verkle_tree import VerkleTree
# from verkle.commitment_scheme import generate_quotient
# from py_ecc import optimized_bls12_381 as b
# from verkle.utils.multicombs import lincomb
# from verkle.randomness_scheme import derive_r
# from verkle.hash_scheme import generate_root_bytes, hash_point_to_field
# from verkle.utils.key_to_path import _key_to_path


# @register_prover("verkle_multiproof")
# class VerkleMultiproofGenerator(BaseProver):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object
#         self.tree = None

#     def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
#         self.tree = tree
#         setup = self.setup_object.setup
#         MODULUS = self.setup_object.MODULUS
#         WIDTH = self.setup_object.WIDTH
        
#         root_commitment = tree.root.commitment_to_children
        
#         # === Collect all paths first ===
#         key_paths = []
#         for key in keys:
#             path = _key_to_path(WIDTH, key)
#             key_paths.append(path)
        
#         # Generate r using the same method as original
#         r = derive_r(generate_root_bytes(root_commitment), key_paths, b.curve_order)
        
#         print(f"DEBUG PROVER: r = {r}")
        
#         # === Now collect nodes with openings ===
#         # Key: (level, comm_x, comm_y) for consistent ordering
#         nodes_map = {}
#         key_values = []
        
#         for key_idx, key in enumerate(keys):
#             path = key_paths[key_idx]
#             node = tree.root
            
#             # Build path commitments
#             path_commitments = [root_commitment]
#             path_nodes = [node]
            
#             for level in range(len(path) - 1):
#                 idx = path[level]
#                 child_data = node.children[idx]
#                 child_node = tree._make_tree_node(child_data)
#                 path_commitments.append(child_node.commitment_to_children)
#                 path_nodes.append(child_node)
#                 node = child_node
            
#             # Now process each level
#             for level in range(len(path)):
#                 idx = path[level]
#                 current_commitment = path_commitments[level]
#                 current_node = path_nodes[level] if level < len(path_nodes) else node
                
#                 node_key = (level, int(current_commitment[0]), int(current_commitment[1]))
                
#                 if node_key not in nodes_map:
#                     # Collect child values
#                     child_values = []
#                     for child in current_node.children:
#                         if child is None:
#                             child_values.append(0)
#                         else:
#                             child_values.append(int.from_bytes(child, byteorder='big'))
                    
#                     nodes_map[node_key] = {
#                         'commitment': current_commitment,
#                         'child_values': child_values,
#                         'openings': {}
#                     }
                
#                 # Determine leaf value
#                 if level < len(path) - 1:
#                     next_commitment = path_commitments[level + 1]
#                     leaf_value = hash_point_to_field(next_commitment, MODULUS)
#                 else:
#                     value = current_node.children[idx] if isinstance(current_node.children[idx], bytes) else b''
#                     if key_idx >= len(key_values):
#                         key_values.append(value)
#                     leaf_value = int.from_bytes(value, byteorder='big')
                
#                 nodes_map[node_key]['openings'][idx] = leaf_value
        
#         # === Sort and aggregate ===
#         sorted_node_keys = sorted(nodes_map.keys())
        
#         total_poly_evaluations = [0] * WIDTH
#         commitments_with_openings = []
        
#         r_power = 1
#         opening_count = 0
        
#         for node_key in sorted_node_keys:
#             node_data = nodes_map[node_key]
#             commitment = node_data['commitment']
#             child_values = node_data['child_values']
#             openings = node_data['openings']
            
#             sorted_openings = sorted(openings.items())
            
#             commitments_with_openings.append({
#                 'commitment': (int(commitment[0]), int(commitment[1])),
#                 'openings': {str(k): v for k, v in sorted_openings},
#                 'level': node_key[0]
#             })
            
#             for idx, leaf_value in sorted_openings:
#                 opening_count += 1
                
#                 # Generate quotient
#                 P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                
#                 # Aggregate
#                 for j in range(WIDTH):
#                     total_poly_evaluations[j] = (
#                         total_poly_evaluations[j] + P_over_Q[j] * r_power
#                     ) % b.curve_order
                
#                 r_power = (r_power * r) % b.curve_order
        
#         print(f"DEBUG PROVER: Total openings = {opening_count}")
        
#         # Generate witness
#         witness = b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
        
#         proof_dict = {
#             'keys': [k.hex() for k in keys],
#             'values': [v.hex() for v in key_values],
#             'root_commitment': (int(root_commitment[0]), int(root_commitment[1])),
#             'commitments_with_openings': commitments_with_openings,
#             'key_paths': key_paths,
#             'witness': (int(witness[0]), int(witness[1])),
#             'num_openings': opening_count
#         }
        
#         return proof_dict, witness

#     # def proof_size(self, proof_dict, witness) -> int:
#     #     witness_size = 48
#     #     num_commitments = len(proof_dict['commitments_with_openings'])
#     #     num_openings = proof_dict['num_openings']
        
#     #     commitments_size = num_commitments * 64
#     #     openings_size = num_openings * 36
#     #     values_size = len(proof_dict['values']) * 32
#     #     paths_size = sum(len(p) for p in proof_dict['key_paths'])
        
#     #     return witness_size + commitments_size + openings_size + values_size + paths_size

#     # def proof_size(self, proof_dict, witness) -> int:
#     #     # BLS12-381 Compressed G1 Point = 48 bytes
#     #     # BLS12-381 Scalar Field Element = 32 bytes
        
#     #     # 1. Witness (Usually a single evaluation point or evaluation proof)
#     #     witness_size = 48 
        
#     #     # 2. Commitments (Compressed points)
#     #     num_commitments = len(proof_dict['commitments_with_openings'])
#     #     commitments_size = num_commitments * 48 
        
#     #     # 3. Openings (Assuming scalar values like 'z' or 'y')
#     #     num_openings = proof_dict['num_openings']
#     #     openings_size = num_openings * 32
        
#     #     # 4. Leaf Values
#     #     values_size = len(proof_dict['values']) * 32
        
#     #     # 5. Paths (Keys)
#     #     paths_size = sum(len(p) for p in proof_dict['key_paths'])
        
#     #     return witness_size + commitments_size + openings_size + values_size + paths_size

#     def proof_size(self, proof_dict, witness) -> int:
#         witness_size = 48 
        
#         # FIXED: Use 48 bytes instead of 64
#         num_commitments = len(proof_dict['commitments_with_openings'])
#         commitments_size = num_commitments * 48 
        
#         # values_size = len(proof_dict['values']) * 32
#         # paths_size = sum(len(p) for p in proof_dict['key_paths'])
        
#         # FIXED: We drop openings_size entirely. 
#         # The multiproof witness evaluates the polynomial without needing 
#         # raw intermediate child values transmitted over the wire.
        
#         return witness_size + commitments_size 

# from registry.provers import BaseProver, register_prover
# from tree.verkle_tree import VerkleTree
# from verkle.commitment_scheme import generate_quotient
# from py_ecc import optimized_bls12_381 as b
# from verkle.utils.multicombs import lincomb
# from verkle.randomness_scheme import derive_r, derive_r_factor_hash
# from verkle.hash_scheme import generate_root_bytes, hash_point_to_field
# from verkle.utils.key_to_path import _key_to_path

# @register_prover("verkle_multiproof")
# class VerkleMultiproofGenerator(BaseProver):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object
#         self.tree = None

#     def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
#         self.tree = tree
#         setup = self.setup_object.setup
#         WIDTH = self.setup_object.WIDTH
        
#         root_commitment = tree.root.commitment_to_children
#         paths_for_r = [_key_to_path(WIDTH, key) for key in keys]
#         r = derive_r(generate_root_bytes(root_commitment), paths_for_r, b.curve_order)
        
#         nodes_map = {}
        
#         for key_idx, key in enumerate(keys):
#             stem = key[:31]
#             suffix = key[31]
#             node = tree.root
#             depth = 0
            
#             while node is not None:
#                 current_commitment = node.commitment_to_children
#                 node_key = (int(current_commitment[0]), int(current_commitment[1]))
                
#                 if node_key not in nodes_map:
#                     nodes_map[node_key] = {
#                         'commitment': current_commitment,
#                         'node_type': node.type,
#                         'child_values': [],
#                         'openings': []
#                     }
                    
#                     if node.type == 'internal' or node.type == 'suffix':
#                         nodes_map[node_key]['child_values'] = [int.from_bytes(c, 'big') if c else 0 for c in node.children]
#                     elif node.type == 'extension':
#                         cv = [1, int.from_bytes(node.stem, 'big'), int.from_bytes(node.child, 'big') if node.child else 0, 0]
#                         cv += [0] * (WIDTH - len(cv))
#                         nodes_map[node_key]['child_values'] = cv
                
#                 if node.type == 'internal':
#                     idx = stem[depth]
#                     nodes_map[node_key]['openings'].append((idx, key_idx, depth))
#                     child_ref = node.children[idx]
#                     if not child_ref: break
#                     node = tree._make_tree_node(child_ref)
#                     depth += 1
#                 elif node.type == 'extension':
#                     idx = 2
#                     nodes_map[node_key]['openings'].append((idx, key_idx, depth))
#                     child_ref = node.child
#                     if not child_ref: break
#                     node = tree._make_tree_node(child_ref)
#                     depth += 1
#                 elif node.type == 'suffix':
#                     idx = suffix
#                     nodes_map[node_key]['openings'].append((idx, key_idx, depth))
#                     break

#         total_poly_evaluations = [0] * WIDTH
#         commitments_out = []
        
#         for comm_key, node_data in nodes_map.items():
#             if comm_key != (int(root_commitment[0]), int(root_commitment[1])):
#                 commitments_out.append(node_data['commitment'])
                
#             child_values = node_data['child_values']
#             openings = node_data['openings']
            
#             for idx, key_idx, depth in openings:
#                 P_over_Q = generate_quotient(child_values, idx, self.setup_object)
#                 r_factor = derive_r_factor_hash(generate_root_bytes(root_commitment), paths_for_r[key_idx], depth, b.curve_order)
                
#                 for j in range(WIDTH):
#                     total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
        
#         witness = b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
        
#         # # STRIPPED PAYLOAD: All path mapping and redundant evaluation data removed.
#         # proof_dict = {
#         #     'commitments': commitments_out,
#         # }
        
#         # return proof_dict, witness

#         key_traversals = {}
#         for key_idx, key in enumerate(keys):
#             stem = key[:31]
#             suffix = key[31]
#             node = tree.root
#             depth = 0
#             traversal = []

#             while node is not None:
#                 current_commitment = node.commitment_to_children
#                 comm_tuple = (int(current_commitment[0]), int(current_commitment[1]))

#                 if node.type == 'internal':
#                     idx = stem[depth]
#                     child_val = int.from_bytes(node.children[idx], 'big') if node.children[idx] else 0
#                     traversal.append((comm_tuple, idx, 'internal', child_val))
#                     child_ref = node.children[idx]
#                     if not child_ref:
#                         break
#                     node = tree._make_tree_node(child_ref)
#                     depth += 1
#                 elif node.type == 'extension':
#                     idx = 2
#                     child_val = int.from_bytes(node.child, 'big') if node.child else 0
#                     traversal.append((comm_tuple, idx, 'extension', child_val))
#                     child_ref = node.child
#                     if not child_ref:
#                         break
#                     node = tree._make_tree_node(child_ref)
#                     depth += 1
#                 elif node.type == 'suffix':
#                     idx = suffix
#                     child_val = int.from_bytes(node.children[idx], 'big') if node.children[idx] else 0
#                     traversal.append((comm_tuple, idx, 'suffix', child_val))
#                     break

#             key_traversals[key_idx] = traversal

#         proof_dict = {
#             'commitments': commitments_out,
#             'key_traversals': key_traversals,
#         }

#         return proof_dict, witness

#     def proof_size(self, proof_dict, witness) -> int:
#         witness_size = 48 
#         num_commitments = len(proof_dict['commitments'])
#         commitments_size = num_commitments * 48 
#         return witness_size + commitments_size

from registry.provers import BaseProver, register_prover
from tree.verkle_tree import VerkleTree
from verkle.commitment_scheme import generate_quotient
from py_ecc import optimized_bls12_381 as b
from verkle.utils.multicombs import lincomb
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from verkle.hash_scheme import generate_root_bytes, hash_point_to_field
from verkle.utils.key_to_path import _key_to_path

@register_prover("verkle_multiproof")
class VerkleMultiproofGenerator(BaseProver):

    def __init__(self, setup_object):
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
        self.tree = tree
        setup = self.setup_object.setup
        WIDTH = self.setup_object.WIDTH
        
        root_commitment = tree.root.commitment_to_children
        paths_for_r = [_key_to_path(WIDTH, key) for key in keys]
        r = derive_r(generate_root_bytes(root_commitment), paths_for_r, b.curve_order)
        
        nodes_map = {}
        
        # ==========================================
        # PASS 1: Node Collection & Evaluation
        # ==========================================
        for key_idx, key in enumerate(keys):
            # --- MODIFIED: Dynamic key chunking ---
            chunks = tree._get_key_chunks(key)
            stem = chunks[:-1]
            suffix = chunks[-1]
            
            node = tree.root
            depth = 0
            
            while node is not None:
                current_commitment = node.commitment_to_children
                node_key = (int(current_commitment[0]), int(current_commitment[1]))
                
                if node_key not in nodes_map:
                    nodes_map[node_key] = {
                        'commitment': current_commitment,
                        'node_type': node.type,
                        'child_values': [],
                        'openings': []
                    }
                    
                    if node.type == 'internal' or node.type == 'suffix':
                        nodes_map[node_key]['child_values'] = [int.from_bytes(c, 'big') if c else 0 for c in node.children]
                    elif node.type == 'extension':
                        # --- MODIFIED: Convert the stem tuple back to bytes ---
                        stem_bytes = bytes(node.stem)
                        cv = [1, int.from_bytes(stem_bytes, 'big'), int.from_bytes(node.child, 'big') if node.child else 0, 0]
                        cv += [0] * (WIDTH - len(cv))
                        nodes_map[node_key]['child_values'] = cv
                
                if node.type == 'internal':
                    idx = stem[depth]
                    nodes_map[node_key]['openings'].append((idx, key_idx, depth))
                    child_ref = node.children[idx]
                    if not child_ref: break
                    node = tree._make_tree_node(child_ref)
                    depth += 1
                elif node.type == 'extension':
                    idx = 2
                    nodes_map[node_key]['openings'].append((idx, key_idx, depth))
                    child_ref = node.child
                    if not child_ref: break
                    node = tree._make_tree_node(child_ref)
                    depth += 1
                elif node.type == 'suffix':
                    idx = suffix
                    nodes_map[node_key]['openings'].append((idx, key_idx, depth))
                    break

        total_poly_evaluations = [0] * WIDTH
        commitments_out = []
        
        for comm_key, node_data in nodes_map.items():
            if comm_key != (int(root_commitment[0]), int(root_commitment[1])):
                commitments_out.append(node_data['commitment'])
                
            child_values = node_data['child_values']
            openings = node_data['openings']
            
            for idx, key_idx, depth in openings:
                P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                r_factor = derive_r_factor_hash(generate_root_bytes(root_commitment), paths_for_r[key_idx], depth, b.curve_order)
                
                for j in range(WIDTH):
                    total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
        
        witness = b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
        
        # ==========================================
        # PASS 2: Traversal Payload Generation
        # ==========================================
        key_traversals = {}
        for key_idx, key in enumerate(keys):
            # --- MODIFIED: Dynamic key chunking ---
            chunks = tree._get_key_chunks(key)
            stem = chunks[:-1]
            suffix = chunks[-1]
            
            node = tree.root
            depth = 0
            traversal = []

            while node is not None:
                current_commitment = node.commitment_to_children
                comm_tuple = (int(current_commitment[0]), int(current_commitment[1]))

                if node.type == 'internal':
                    idx = stem[depth]
                    child_val = int.from_bytes(node.children[idx], 'big') if node.children[idx] else 0
                    traversal.append((comm_tuple, idx, 'internal', child_val))
                    child_ref = node.children[idx]
                    if not child_ref:
                        break
                    node = tree._make_tree_node(child_ref)
                    depth += 1
                elif node.type == 'extension':
                    idx = 2
                    child_val = int.from_bytes(node.child, 'big') if node.child else 0
                    traversal.append((comm_tuple, idx, 'extension', child_val))
                    child_ref = node.child
                    if not child_ref:
                        break
                    node = tree._make_tree_node(child_ref)
                    depth += 1
                elif node.type == 'suffix':
                    idx = suffix
                    child_val = int.from_bytes(node.children[idx], 'big') if node.children[idx] else 0
                    traversal.append((comm_tuple, idx, 'suffix', child_val))
                    break

            key_traversals[key_idx] = traversal

        proof_dict = {
            'commitments': commitments_out,
            'key_traversals': key_traversals,
        }

        return proof_dict, witness

    def proof_size(self, proof_dict, witness) -> int:
        witness_size = 48 
        num_commitments = len(proof_dict['commitments'])
        commitments_size = num_commitments * 48 
        return witness_size + commitments_size