import unittest
from unittest.mock import patch

from prover.stark_merkle import MPTSTARKProver
from verifier.stark_verification import MPTSTARKVerifier
from zkstark_risc0 import bridge


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.root = bytes(range(32))
        self.key = b"\xab"
        self.value = b"value"
        self.node = bytes([201, 130, 32, 171, 133, 118, 97, 108, 117, 101])

    def test_prover_passes_private_nodes_to_host(self):
        class Tree:
            hash_fn_name = "keccak"
            width = 16
            _secure = False

            def root_hash(inner):
                return self.root

            def get_proof_tree(inner, key):
                return [self.node]

            def get(inner, key):
                return self.value

        with patch.object(bridge, "_call", return_value={"proof": "010203"}) as host:
            receipts, root = MPTSTARKProver().generate_proof(Tree(), [self.key])
        self.assertEqual((receipts, root), ([b"\x01\x02\x03"], self.root))
        self.assertEqual(MPTSTARKProver().proof_size(receipts, root), 3)
        sent = host.call_args.args[0]
        self.assertEqual(sent["nodes"], [self.node.hex()])
        self.assertEqual(sent["root"], self.root.hex())

    def test_verifier_binds_caller_statement_and_batch(self):
        verifier = MPTSTARKVerifier()
        proof = ([b"receipt"], self.root)
        with patch.object(bridge, "verify", return_value=True) as check:
            self.assertTrue(verifier.verify_proof([self.value], [self.key], self.root, proof))
            check.assert_called_once_with(b"receipt", self.root, self.key, self.value)
            self.assertFalse(verifier.verify_proof([self.value], [self.key], bytes(32), proof))
            self.assertFalse(verifier.verify_proof([self.value], [self.key, b"x"], self.root, proof))

    def test_host_failure_is_not_a_valid_proof(self):
        with patch.object(bridge, "_call", side_effect=RuntimeError("host unavailable")):
            self.assertFalse(bridge.verify(b"receipt", self.root, self.key, self.value))


if __name__ == "__main__":
    unittest.main()
