"""Private-witness MPT membership ZK-STARK prover (RISC Zero composite receipt)."""

from registry.provers import BaseProver, register_prover
from merkle.node import Node
from zkstark_risc0 import bridge


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
        if not isinstance(commitments, list) or any(not isinstance(p, bytes) for p in commitments):
            raise ValueError("expected serialized ZK-STARK receipts")
        return sum(len(receipt) for receipt in commitments)

    def get_setup_params(self):
        return {"backend": "RISC Zero 3.0.6", "receipt_kind": "composite", "guest": "mpt_membership"}
