from registry.verifiers import BaseVerifier, register_verifier
from verkle.randomness_scheme import derive_r
from py_ecc import optimized_bls12_381 as b
from verkle.hash_scheme import generate_root_bytes

@register_verifier("verkle_multiproof_optimized")
class VerkleMultiproofVerifier(BaseVerifier):

    def __init__(self, setup_object):
        self.setup_object = setup_object

    def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
        proof_dict, witness_raw = proof

        setup = self.setup_object.setup
        MODULUS = self.setup_object.MODULUS
        LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
        WIDTH = self.setup_object.WIDTH
        field = self.setup_object.field

        unique_commitments = proof_dict['unique_commitments']
        openings = proof_dict['openings']
        key_paths = proof_dict['key_paths']
        root_commitment = proof_dict['root_commitment']
        witness_tuple = proof_dict['witness']

        root = (b.FQ(root_commitment[0]), b.FQ(root_commitment[1]))
        r = derive_r(generate_root_bytes(root), key_paths, b.curve_order)

        pairing_check = b.FQ12.one()
        r_power = 1

        for opening in openings:
            comm_data = unique_commitments[opening['commitment_idx']]
            commitment = comm_data['commitment']
            idx = opening['opening_idx']
            leaf_value = opening['value']

            comm_point = (b.FQ(commitment[0]), b.FQ(commitment[1]), b.FQ.one())
            neg_leaf_times_g1 = b.multiply(b.G1, (MODULUS - leaf_value) % MODULUS)
            comm_minus_leaf = b.add(comm_point, neg_leaf_times_g1)
            comm_minus_leaf_times_r = b.multiply(comm_minus_leaf, r_power)

            lagrange_inv = field.inv(LAGRANGE_POLYS[idx][-1])
            Z_comm = b.multiply(setup[3][idx], lagrange_inv)

            pairing_check *= b.pairing(Z_comm, comm_minus_leaf_times_r, False)
            r_power = (r_power * r) % b.curve_order

        global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
        witness_point = (b.FQ(witness_tuple[0]), b.FQ(witness_tuple[1]), b.FQ.one())

        pairing_check *= b.pairing(b.neg(global_Z_comm), witness_point, False)
        result = b.final_exponentiate(pairing_check)

        if result != b.FQ12.one():
            print(f"Multiproof verification failed!")
            return False

        print("Multiproof verification PASSED!")
        return True