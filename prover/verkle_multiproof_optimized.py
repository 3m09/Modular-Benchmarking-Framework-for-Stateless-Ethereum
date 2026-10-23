from registry.provers import BaseProver, register_prover
from tree.verkle_tree import VerkleTree
from verkle.commitment_scheme import generate_quotient
from py_ecc import optimized_bls12_381 as b
from verkle.utils.multicombs import lincomb
from verkle.randomness_scheme import derive_r
from verkle.hash_scheme import generate_root_bytes, hash_point_to_field
from verkle.utils.key_to_path import _key_to_path

@register_prover("verkle_multiproof_optimized")
class VerkleMultiproofGenerator(BaseProver):

    def __init__(self, setup_object):
        self.setup_object = setup_object
        self.tree = None

    def generate_proof(self, tree: VerkleTree, keys: list[bytes]):
        self.tree = tree
        setup = self.setup_object.setup
        MODULUS = self.setup_object.MODULUS
        WIDTH = self.setup_object.WIDTH

        root_commitment = tree.root.commitment_to_children

        # === Collect all paths first ===
        key_paths = []
        for key in keys:
            path = _key_to_path(WIDTH, key)
            key_paths.append(path)

        r = derive_r(generate_root_bytes(root_commitment), key_paths, b.curve_order)

        # === Collect unique commitments and openings ===
        commitment_map = {}  # (level, x, y) -> idx
        unique_commitments = []  # [{commitment, child_values, level}]
        openings = []  # [{commitment_idx, opening_idx, value, level}]
        key_values = []

        for key_idx, key in enumerate(keys):
            path = key_paths[key_idx]
            node = tree.root
            path_commitments = [root_commitment]
            path_nodes = [node]

            for level in range(len(path) - 1):
                idx = path[level]
                child_data = node.children[idx]
                child_node = tree._make_tree_node(child_data)
                path_commitments.append(child_node.commitment_to_children)
                path_nodes.append(child_node)
                node = child_node

            for level in range(len(path)):
                idx = path[level]
                current_commitment = path_commitments[level]
                current_node = path_nodes[level] if level < len(path_nodes) else node
                comm_key = (level, int(current_commitment[0]), int(current_commitment[1]))

                if comm_key not in commitment_map:
                    # Add unique commitment
                    child_values = []
                    for child in current_node.children:
                        if child is None:
                            child_values.append(0)
                        else:
                            child_values.append(int.from_bytes(child, byteorder='big'))
                    commitment_map[comm_key] = len(unique_commitments)
                    unique_commitments.append({
                        'commitment': (int(current_commitment[0]), int(current_commitment[1])),
                        'child_values': child_values,
                        'level': level
                    })
                comm_idx = commitment_map[comm_key]

                # Determine leaf value
                if level < len(path) - 1:
                    next_commitment = path_commitments[level + 1]
                    leaf_value = hash_point_to_field(next_commitment, MODULUS)
                else:
                    value = current_node.children[idx] if isinstance(current_node.children[idx], bytes) else b''
                    if key_idx >= len(key_values):
                        key_values.append(value)
                    leaf_value = int.from_bytes(value, byteorder='big')

                openings.append({
                    'commitment_idx': comm_idx,
                    'opening_idx': idx,
                    'value': leaf_value,
                    'level': level
                })

        # === Aggregate polynomials ===
        total_poly_evaluations = [0] * WIDTH
        r_power = 1
        for opening in openings:
            comm_data = unique_commitments[opening['commitment_idx']]
            P_over_Q = generate_quotient(comm_data['child_values'], opening['opening_idx'], self.setup_object)
            for j in range(WIDTH):
                total_poly_evaluations[j] = (
                    total_poly_evaluations[j] + P_over_Q[j] * r_power
                ) % b.curve_order
            r_power = (r_power * r) % b.curve_order

        witness = b.normalize(lincomb(setup[2], total_poly_evaluations, b.add, b.Z1))

        proof_dict = {
            'keys': [k.hex() for k in keys],
            'values': [v.hex() for v in key_values],
            'root_commitment': (int(root_commitment[0]), int(root_commitment[1])),
            'unique_commitments': unique_commitments,
            'openings': openings,
            'key_paths': key_paths,
            'witness': (int(witness[0]), int(witness[1])),
            'num_openings': len(openings)
        }

        return proof_dict, witness

    def proof_size(self, proof_dict, witness) -> int:
        witness_size = 48
        num_commitments = len(proof_dict['unique_commitments'])
        num_openings = proof_dict['num_openings']
        commitments_size = num_commitments * 64
        openings_size = num_openings * 36
        values_size = len(proof_dict['values']) * 32
        paths_size = sum(len(p) for p in proof_dict['key_paths'])
        return witness_size + commitments_size + openings_size + values_size + paths_size