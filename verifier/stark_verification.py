"""Verify real composite ZK-STARK receipts against the caller's MPT claim."""

from registry.verifiers import BaseVerifier, register_verifier
from zkstark_risc0 import bridge


@register_verifier("zkstarkmerkle")
class MPTSTARKVerifier(BaseVerifier):
    def __init__(self, setup=None):
        self.setup = setup

    def verify_proof(self, values, keys, root, proof, setup=None):
        if (
            not isinstance(root, bytes)
            or len(root) != 32
            or not isinstance(values, list)
            or not isinstance(keys, list)
            or not values
            or len(values) != len(keys)
            or not isinstance(proof, tuple)
            or len(proof) != 2
        ):
            return False
        receipts, witness_root = proof
        if witness_root != root or not isinstance(receipts, list) or len(receipts) != len(keys):
            return False
        return all(bridge.verify(raw, root, key, value) for raw, key, value in zip(receipts, keys, values))

    def verify_lookup(self, raw, root, key, value):
        return bridge.verify(raw, root, key, value)

    def verify_with_proof_dict(self, proof, public_inputs):
        if not isinstance(public_inputs, dict):
            return False
        return self.verify_lookup(
            proof, public_inputs.get("root"), public_inputs.get("key"), public_inputs.get("value")
        )
