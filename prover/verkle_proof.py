# from registry.provers import BaseProver, register_prover
# from tree.verkle_tree import VerkleTree
# from verkle.commitment_scheme import generate_quotient
# from py_ecc import optimized_bls12_381 as b
# from verkle.utils.multicombs import lincomb
# from verkle.randomness_scheme import derive_r, derive_r_factor_hash
# from verkle.hash_scheme import generate_root_bytes
# from verkle.utils.key_to_path import _key_to_path

# @register_prover("verkle")
# class VerkleProofGenerator(BaseProver):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object
#         self.tree = None

#     def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
#         self.tree = tree
#         setup = self.setup_object.setup
#         committee_root = tree.root.commitment_to_children
#         # Generate a random r value;
#         # to create a random linear combination
#         r = derive_r(generate_root_bytes(committee_root), [_key_to_path(tree.width, k) for k in keys], b.curve_order)
#         #print("r", r)
        
#         # Total polynomial that we are evaluating
#         total_poly_evaluations = [0] * tree.width
#         # The set of all intermediate commitments
#         commitments = [tree.get_proof_tree(k) for k in keys]

#         for key in keys:
#             path = _key_to_path(tree.width, key)
#             # Walk from top to bottom of the tree
#             node = tree.root
#             for i in range(len(path)):
#                 # Generate the quotient polynomial for this node
#                 child_values = []
#                 all_none = True
#                 for child in node.children:
#                     if child is None:
#                         child_values.append(0)
#                     else:
#                         all_none = False
#                         child_values.append(int.from_bytes(child, byteorder='big'))
#                 P_over_Q = generate_quotient(child_values, path[i], self.setup_object)
#                 if all_none:
#                     print('all children are None')
                
#                 # Add to the total polynomial with appropriate r^level factor
#                 r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), path, i, b.curve_order)
#                 for j in range(tree.width):
#                     total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                
#                 # Move to the next node
#                 # print("At level", i, "path index", path[i])
#                 node = tree._make_tree_node(node.children[path[i]]) if i < len(path) - 1 else None
                
#         # Generate a polynomial commitment for the result
#         return commitments, b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
    
#     def proof_size(self, commitments, witness) -> int:
#         return self.tree.get_proof_size(commitments, witness)

# from registry.provers import BaseProver, register_prover
# from tree.verkle_tree import VerkleTree
# from verkle.commitment_scheme import generate_quotient
# from py_ecc import optimized_bls12_381 as b
# from verkle.utils.multicombs import lincomb
# from verkle.randomness_scheme import derive_r, derive_r_factor_hash
# from verkle.hash_scheme import generate_root_bytes
# from verkle.utils.key_to_path import _key_to_path

# @register_prover("verkle")
# class VerkleProofGenerator(BaseProver):

#     def __init__(self, setup_object):
#         self.setup_object = setup_object
#         self.tree = None

#     def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
#         self.tree = tree
#         setup = self.setup_object.setup
#         committee_root = tree.root.commitment_to_children
        
#         commitments = [tree.get_proof_tree(k) for k in keys]
        
#         # We maintain the 32-byte paths strictly for the deterministic randomness scheme
#         paths_for_r = [_key_to_path(tree.width, k) for k in keys]
#         r = derive_r(generate_root_bytes(committee_root), paths_for_r, b.curve_order)
        
#         total_poly_evaluations = [0] * tree.width

#         for key_idx, key in enumerate(keys):
#             stem = key[:31]
#             suffix = key[31]
#             node = tree.root
#             depth = 0
            
#             # The depth of the compressed path
#             path_length = len(commitments[key_idx]) + 1 
            
#             for level in range(path_length):
#                 if node.type == 'internal':
#                     idx = stem[depth]
#                     child_values = [int.from_bytes(c, 'big') if c else 0 for c in node.children]
#                     P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                    
#                     r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), paths_for_r[key_idx], level, b.curve_order)
#                     for j in range(tree.width):
#                         total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                    
#                     node = tree._make_tree_node(node.children[idx])
#                     depth += 1
                    
#                 elif node.type == 'extension':
#                     # We evaluate at index 2, which is where the child hash sits in the polynomial
#                     idx = 2 
#                     child_values = [
#                         1,
#                         int.from_bytes(node.stem, 'big'),
#                         int.from_bytes(node.child, 'big') if node.child else 0,
#                         0
#                     ]
#                     # Pad to standard width for the FFT/quotient generator
#                     child_values += [0] * (self.setup_object.WIDTH - len(child_values))
                    
#                     P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                    
#                     r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), paths_for_r[key_idx], level, b.curve_order)
#                     for j in range(tree.width):
#                         total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                    
#                     node = tree._make_tree_node(node.child)
                    
#                 elif node.type == 'suffix':
#                     idx = suffix
#                     child_values = [int.from_bytes(c, 'big') if c else 0 for c in node.children]
#                     P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                    
#                     r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), paths_for_r[key_idx], level, b.curve_order)
#                     for j in range(tree.width):
#                         total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                    
#                     break 
                
#         return commitments, b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
    
#     def proof_size(self, commitments, witness) -> int:
#         return self.tree.get_proof_size(commitments, witness)

from registry.provers import BaseProver, register_prover
from tree.verkle_tree import VerkleTree
from verkle.commitment_scheme import generate_quotient
from py_ecc import optimized_bls12_381 as b
from verkle.utils.multicombs import lincomb
from verkle.randomness_scheme import derive_r, derive_r_factor_hash
from verkle.hash_scheme import generate_root_bytes
from verkle.utils.key_to_path import _key_to_path

@register_prover("verkle")
class VerkleProofGenerator(BaseProver):

    def __init__(self, setup_object):
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
        self.tree = tree
        setup = self.setup_object.setup
        committee_root = tree.root.commitment_to_children
        
        commitments = [tree.get_proof_tree(k) for k in keys]
        
        paths_for_r = [_key_to_path(tree.width, k) for k in keys]
        r = derive_r(generate_root_bytes(committee_root), paths_for_r, b.curve_order)
        
        total_poly_evaluations = [0] * tree.width

        for key_idx, key in enumerate(keys):
            # --- MODIFIED: Use tree's chunking logic ---
            chunks = tree._get_key_chunks(key)
            stem = chunks[:-1]
            suffix = chunks[-1]
            
            node = tree.root
            depth = 0
            
            path_length = len(commitments[key_idx]) + 1 
            
            for level in range(path_length):
                if node.type == 'internal':
                    idx = stem[depth]
                    child_values = [int.from_bytes(c, 'big')  if c else 0 for c in node.children]
                    P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                    
                    r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), paths_for_r[key_idx], level, b.curve_order)
                    for j in range(tree.width):
                        total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                    
                    node = tree._make_tree_node(node.children[idx])
                    depth += 1
                    
                elif node.type == 'extension':
                    idx = 2 
                    # --- MODIFIED: Convert the tuple node.stem to bytes first ---
                    stem_bytes = bytes(node.stem)
                    child_values = [
                        1,
                        int.from_bytes(stem_bytes, 'big') , 
                        int.from_bytes(node.child, 'big')  if node.child else 0,
                        0
                    ]
                    child_values += [0] * (self.setup_object.WIDTH - len(child_values))
                    
                    P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                    
                    r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), paths_for_r[key_idx], level, b.curve_order)
                    for j in range(tree.width):
                        total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                    
                    node = tree._make_tree_node(node.child)
                    
                elif node.type == 'suffix':
                    idx = suffix
                    child_values = [int.from_bytes(c, 'big') if c else 0 for c in node.children]
                    P_over_Q = generate_quotient(child_values, idx, self.setup_object)
                    
                    r_factor = derive_r_factor_hash(generate_root_bytes(committee_root), paths_for_r[key_idx], level, b.curve_order)
                    for j in range(tree.width):
                        total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % b.curve_order
                    
                    break 
                
        return commitments, b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))
    
    def proof_size(self, commitments, witness) -> int:
        return self.tree.get_proof_size(commitments, witness)