from registry.provers import register_prover
from prover.verkle_proof_eip6800 import VerkleProofGeneratorEIP6800
from tree.verkle_tree_eip6800 import VerkleTreeEIP6800
from verkle.commitment_scheme import generate_quotient
from verkle.eip6800 import derive_opening_challenge
from verkle.native_bls import msm, native_setup
from py_ecc import optimized_bls12_381 as b


@register_prover("verkle_eip6800")
class VerkleProofGeneratorEIP6800Native(VerkleProofGeneratorEIP6800):
    """
    Same openings, transcript and quotient polynomials as the py_ecc reference
    prover (verkle_eip6800_pyecc); the multi-scalar multiplication that
    commits to the aggregated quotient runs in blst. The witness is returned
    in its 48-byte compressed encoding, i.e., exactly what is transmitted.
    """

    def generate_proof(self, tree: VerkleTreeEIP6800, keys: list[bytes]):
        self.tree = tree
        MODULUS = self.setup_object.MODULUS
        root = tree.root.commitment_to_children

        commitments, openings = self.collect_openings(tree, keys)
        r = derive_opening_challenge(root, [(c, idx, y) for c, idx, y, _ in openings], b.curve_order)

        total_poly_evaluations = [0] * tree.width
        r_factor = 1
        for _, idx, _, evals in openings:
            P_over_Q = generate_quotient(evals, idx, self.setup_object)
            for j in range(tree.width):
                total_poly_evaluations[j] = (total_poly_evaluations[j] + P_over_Q[j] * r_factor) % MODULUS
            r_factor = r_factor * r % MODULUS

        native = native_setup(self.setup_object)
        witness = msm(native["g1_lagrange"], total_poly_evaluations).compress()
        return commitments, witness
