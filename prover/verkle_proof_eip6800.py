from registry.provers import BaseProver, register_prover
from tree.verkle_tree_eip6800 import VerkleTreeEIP6800
from verkle.commitment_scheme import generate_quotient
from verkle.utils.multicombs import lincomb
from verkle.hash_scheme import generate_root_bytes
from verkle.eip6800 import (
    STEM_LENGTH,
    stem_path,
    suffix_level_evals,
    suffix_opening_path,
    derive_opening_challenge,
)
from py_ecc import optimized_bls12_381 as b


@register_prover("verkle_eip6800")
class VerkleProofGeneratorEIP6800(BaseProver):
    """
    Batched KZG multiproof over every opening on the paths of `keys`:
        internal node      -> child field element at stem digit [depth]
        leaf node          -> index 0 (marker 1), index 1 (stem), index 2 + j (top suffix commitment)
        upper suffix level -> field element of the suffix commitment below
        suffix level 0     -> lower and upper half of the 32-byte value
    For width 256 the suffix levels are just [C1, C2], as in EIP-6800.
    Openings shared between keys are included once.
    """

    def __init__(self, setup_object):
        self.setup_object = setup_object
        self.tree = None

    def collect_openings(self, tree: VerkleTreeEIP6800, keys: list[bytes]):
        openings = []   # (commitment, idx, y, evaluation vector)
        seen = set()
        commitments = []

        def add(commitment, evals, idx):
            tag = (generate_root_bytes(commitment), idx)
            if tag not in seen:
                seen.add(tag)
                openings.append((commitment, idx, evals[idx], evals))

        for key in keys:
            stem = bytes(key[:STEM_LENGTH])
            suffix = key[STEM_LENGTH]
            path = tree.get_path_nodes(stem)
            if path is None:
                raise KeyError("Proofs of absence are not supported: " + key.hex())
            leaf = path[-1]
            digits = stem_path(stem, tree.width)

            for depth, node in enumerate(path[:-1]):
                evals = [int.from_bytes(c, 'big') if c else 0 for c in node.children]
                add(node.commitment_to_children, evals, digits[depth])

            positions, leaf_slot = suffix_opening_path(suffix, tree.width)
            leaf_evals = tree.leaf_commitment_values(leaf)
            for idx in (0, 1, leaf_slot):
                add(leaf.commitment_to_children, leaf_evals, idx)

            level_evals = suffix_level_evals(leaf.children, leaf.suffix_commitments, tree.width, self.setup_object)
            suffix_chain = []
            for level in range(len(positions) - 1, -1, -1):
                block, idx = positions[level]
                c = leaf.suffix_commitments[level][block]
                add(c, level_evals[level][block], idx)
                if level == 0:
                    add(c, level_evals[level][block], idx + 1)
                suffix_chain.append(c)

            commitments.append([n.commitment_to_children for n in path[1:]] + suffix_chain)

        return commitments, openings

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

        witness = b.normalize(lincomb(self.setup_object.setup[2], total_poly_evaluations, b.add, b.Z1))
        return commitments, witness

    def proof_size(self, commitments, witness) -> int:
        """Unique commitments (shared path nodes sent once) + the witness, 48 bytes each compressed."""
        COMPRESSED_POINT_SIZE = 48
        unique = {generate_root_bytes(c) for key_commitments in commitments for c in key_commitments}
        return (len(unique) + 1) * COMPRESSED_POINT_SIZE
