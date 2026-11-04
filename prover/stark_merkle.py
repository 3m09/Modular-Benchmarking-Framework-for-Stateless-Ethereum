"""Private-witness MPT membership ZK-STARK prover (RISC Zero composite receipt)."""

import json

from registry.provers import BaseProver, register_prover
from merkle.node import Node
from zkstark_risc0 import bridge


def _binary_size(obj, key=None):
    """4 bytes per u32 word in a decoded RISC Zero receipt, skipping the journal."""
    if key == "journal":
        return 0
    if isinstance(obj, dict):
        return sum(_binary_size(v, k) for k, v in obj.items())
    if isinstance(obj, list):
        if obj and all(isinstance(x, int) for x in obj):
            return 4 * len(obj)
        return sum(_binary_size(x) for x in obj)
    return 0


@register_prover("zkstarkmerkle")
class MPTSTARKProver(BaseProver):
    def __init__(self, setup=None):
        self.setup = setup

    def generate_proof(self, tree, keys):
        if getattr(tree, "hash_fn_name", None) != "keccak" or getattr(tree, "width", None) != 16:
            raise ValueError("ZK-STARK backend requires a hexary Keccak MPT")
        if getattr(tree, "_secure", False):
            raise ValueError("hash secure-trie keys before using this backend")
        if not isinstance(keys, list) or not keys:
            raise ValueError("at least one key is required")
        root = tree.root_hash()
        if not isinstance(root, bytes) or len(root) != 32:
            raise ValueError("expected 32-byte root hash")
        receipts = []
        for key in keys:
            nodes = tree.get_proof_tree(key)
            # The proof collector already validates the path; decode its
            # terminal node directly so inline-root tries work as well.
            value = Node.decode(nodes[-1]).data
            receipts.append(bridge.prove(nodes, root, key, value))
        return receipts, root

    def proof_size(self, commitments, witness):
        """
        Binary size of the receipts. The host transports receipts as JSON (about
        2.6x larger); here every u32 word (segment seals, claim digests,
        verifier parameters) counts 4 bytes. The journal is excluded: it is the
        statement (root, key, value) that the verifier already holds.
        """
        if not isinstance(commitments, list) or any(not isinstance(p, bytes) for p in commitments):
            raise ValueError("expected serialized ZK-STARK receipts")
        return sum(_binary_size(json.loads(receipt)) for receipt in commitments)

    def get_setup_params(self):
        return {"backend": "RISC Zero 3.0.6", "receipt_kind": "composite", "guest": "mpt_membership"}
