from registry.verifiers import BaseVerifier, register_verifier
from verkle.hash_scheme import generate_root_bytes
from verkle.eip6800 import (
    STEM_LENGTH,
    split_leaf_value,
    stem_path,
    suffix_level_sizes,
    suffix_opening_path,
    commitment_to_field,
    derive_opening_challenge,
)
from py_ecc import optimized_bls12_381 as b


@register_verifier("verkle_eip6800")
class VerkleProofVerifierEIP6800(BaseVerifier):
    """Verifies proofs from VerkleProofGeneratorEIP6800 (see that class for the opening layout)."""

    def __init__(self, setup_object):
        self.setup_object = setup_object

    def collect_openings(self, values, keys, root, commitments):
        openings = []   # (commitment, idx, y)
        seen = {}

        def add(commitment, idx, y):
            if commitment is None:
                raise ValueError("Proof contains an empty commitment on an opened path")
            tag = (generate_root_bytes(commitment), idx)
            if tag in seen:
                if seen[tag] != y:
                    raise ValueError("Conflicting claims for the same opening")
                return
            seen[tag] = y
            openings.append((commitment, idx, y))

        if len(values) != len(keys) or len(commitments) != len(keys):
            raise ValueError("keys, values and proof commitments must have the same length")

        WIDTH = self.setup_object.WIDTH
        num_suffix_levels = len(suffix_level_sizes(WIDTH))

        for key, value, c in zip(keys, values, commitments):
            if len(key) != 32 or len(value) != 32:
                raise ValueError("Keys and values must be exactly 32 bytes")
            stem = bytes(key[:STEM_LENGTH])
            suffix = key[STEM_LENGTH]
            digits = stem_path(stem, WIDTH)
            if len(c) < num_suffix_levels + 1 or len(c) - num_suffix_levels > len(digits):
                raise ValueError("Malformed commitment path")

            path = [root] + c[:-num_suffix_levels]      # root, internal..., leaf
            suffix_chain = c[-num_suffix_levels:]       # top-down
            for depth in range(len(path) - 1):
                add(path[depth], digits[depth], commitment_to_field(path[depth + 1], self.setup_object))

            positions, leaf_slot = suffix_opening_path(suffix, WIDTH)
            leaf_comm = path[-1]
            add(leaf_comm, 0, 1)
            add(leaf_comm, 1, int.from_bytes(stem, 'big'))
            add(leaf_comm, leaf_slot, commitment_to_field(suffix_chain[0], self.setup_object))

            # Walk the suffix levels top-down, each opening to the field element of the one below
            for i, level in enumerate(range(len(positions) - 1, 0, -1)):
                _, idx = positions[level]
                add(suffix_chain[i], idx, commitment_to_field(suffix_chain[i + 1], self.setup_object))

            _, lower_idx = positions[0]
            lower, upper = split_leaf_value(value)
            add(suffix_chain[-1], lower_idx, lower)
            add(suffix_chain[-1], lower_idx + 1, upper)

        return openings

    def verify_proof(self, values: list[bytes], keys: list[bytes], root, proof):
        commitments, witness = proof
        setup = self.setup_object.setup
        MODULUS = self.setup_object.MODULUS
        WIDTH = self.setup_object.WIDTH
        LAGRANGE_POLYS = self.setup_object.LAGRANGE_POLYS

        openings = self.collect_openings(values, keys, root, commitments)
        r = derive_opening_challenge(root, openings, b.curve_order)

        # Group openings by evaluation index: sum_i r_i * (C_i - y_i*G1) per index, one pairing each
        grouped = {}
        r_factor = 1
        for comm, idx, y in openings:
            point_sum, y_sum = grouped.get(idx, (b.Z1, 0))
            point_sum = b.add(point_sum, b.multiply((comm[0], comm[1], b.FQ.one()), r_factor))
            grouped[idx] = (point_sum, (y_sum + r_factor * y) % MODULUS)
            r_factor = r_factor * r % MODULUS

        pairing_check = b.FQ12.one()
        for idx, (point_sum, y_sum) in grouped.items():
            lhs = b.add(point_sum, b.neg(b.multiply(b.G1, y_sum)))
            Z_comm = b.multiply(setup[3][idx], self.setup_object.field.inv(LAGRANGE_POLYS[idx][-1]))
            pairing_check *= b.pairing(Z_comm, lhs, False)

        global_Z_comm = b.add(setup[1][WIDTH], b.neg(setup[1][0]))
        pairing_check *= b.pairing(b.neg(global_Z_comm), (witness[0], witness[1], b.FQ.one()), False)
        o = b.final_exponentiate(pairing_check)

        assert o == b.FQ12.one(), "Pairing check failed."
        return o == b.FQ12.one()
