"""Real composite-receipt test; requires built RISC Zero host and adequate RAM."""

import os
from tempfile import TemporaryDirectory
import unittest

from prover.stark_merkle import MPTSTARKProver
from tree.merkle_tree import MerklePatriciaTrie
from verifier.stark_verification import MPTSTARKVerifier


@unittest.skipUnless(os.environ.get("RUN_ZKSTARK_E2E") == "1", "set RUN_ZKSTARK_E2E=1")
class EndToEndTests(unittest.TestCase):
    def test_private_witness_receipt_and_tampering(self):
        with TemporaryDirectory() as directory:
            tree = MerklePatriciaTrie(width=16, db_path=directory, hash_fn="keccak")
            try:
                key, value = b"\xab", b"value"
                tree.insert(key, value)
                receipts, root = MPTSTARKProver().generate_proof(tree, [key])
                verifier = MPTSTARKVerifier()
                self.assertTrue(verifier.verify_proof([value], [key], root, (receipts, root)))
                self.assertFalse(verifier.verify_proof([value], [key], bytes(32), (receipts, root)))
                self.assertFalse(verifier.verify_proof([value], [b"\xac"], root, (receipts, root)))
                self.assertFalse(verifier.verify_proof([b"wrong"], [key], root, (receipts, root)))
            finally:
                tree.db.close()

    def test_extension_branch_leaf_receipt(self):
        with TemporaryDirectory() as directory:
            tree = MerklePatriciaTrie(width=16, db_path=directory, hash_fn="keccak")
            try:
                key, value = b"\xab", b"value" * 13
                tree.insert(key, value)
                tree.insert(b"\xac", b"other" * 13)
                receipts, root = MPTSTARKProver().generate_proof(tree, [key])
                self.assertTrue(MPTSTARKVerifier().verify_proof([value], [key], root, (receipts, root)))
            finally:
                tree.db.close()
