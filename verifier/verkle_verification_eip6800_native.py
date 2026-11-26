from registry.verifiers import register_verifier
from verifier.verkle_verification_eip6800 import VerkleProofVerifierEIP6800
from verkle.eip6800 import derive_opening_challenge
from verkle.native_bls import g1_compress, g1_uncompress, native_setup, pairing_product_equals
from py_ecc import optimized_bls12_381 as b


@register_verifier("verkle_eip6800")
class VerkleProofVerifierEIP6800Native(VerkleProofVerifierEIP6800):
    """
    Same checks as the py_ecc reference verifier (verkle_eip6800_pyecc), with
    the group operations and pairings in blst. Every commitment of the proof
    and the witness are deserialized from their compressed encoding, including
    the subgroup check, as a verifier receiving the proof would do.

    Check: prod_idx e(sum_i r^i (C_i - y_i G1), [Z_idx]G2) == e(W, [s^W - 1]G2),
    with one Miller loop per distinct evaluation index and one final
    exponentiation.
    """

    def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
        commitments, witness_bytes = proof
        MODULUS = self.setup_object.MODULUS
        LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS
        native = native_setup(self.setup_object)

        openings = self.collect_openings(values, keys, root, commitments)
        r = derive_opening_challenge(root, openings, b.curve_order)

        decoded = {}     # each distinct commitment is deserialized once

        def point(commitment):
            enc = g1_compress(commitment)
            if enc not in decoded:
                decoded[enc] = g1_uncompress(enc)
            return decoded[enc]

        grouped = {}
        r_factor = 1
        for comm, idx, y in openings:
            point_sum, y_sum = grouped.get(idx, (None, 0))
            term = point(comm).scalar_mul(r_factor)
            grouped[idx] = (term if point_sum is None else point_sum + term, (y_sum + r_factor * y) % MODULUS)
            r_factor = r_factor * r % MODULUS

        lhs = []
        for idx, (point_sum, y_sum) in grouped.items():
            lhs_point = point_sum + (-native["G1"].scalar_mul(y_sum)) if y_sum else point_sum
            z_comm = native["g2_lagrange"][idx].scalar_mul(self.setup_object.field.inv(LAGRANGE_POLYS[idx][-1]))
            lhs.append((lhs_point, z_comm))

        witness = g1_uncompress(witness_bytes)
        global_z = native["g2_s_W"] + (-native["g2_one"])
        ok = pairing_product_equals(lhs, (witness, global_z))
        assert ok, "Pairing check failed."
        return ok
