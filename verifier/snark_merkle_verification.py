import atexit
import json
import os
import subprocess
from registry.verifiers import BaseVerifier, register_verifier
from prover.snark_merkle_poseidon_proof import KEYS_BATCH_SIZE, public_signals

VKEY_PATH = "verification_key_batch_16.json"
WORKER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zkSNARK", "groth16_worker.js")


class _Groth16Worker:
    """Persistent snarkjs process, so Node.js start-up is not part of the verification time."""

    def __init__(self):
        if not os.path.exists(VKEY_PATH):
            raise FileNotFoundError(f"Verification key not found at: {VKEY_PATH}")
        self._proc = subprocess.Popen(
            ["node", WORKER, VKEY_PATH],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )
        atexit.register(self.close)

    def verify(self, public: list[str], proof: dict) -> bool:
        self._proc.stdin.write(json.dumps({"public": public, "proof": proof}) + "\n")
        self._proc.stdin.flush()
        return self._proc.stdout.readline().strip() == "true"

    def close(self):
        if self._proc.poll() is None:
            self._proc.stdin.close()
            self._proc.wait()


_worker = None


def warm_up():
    """Starts the worker outside the timed region."""
    global _worker
    if _worker is None:
        _worker = _Groth16Worker()
    return _worker


@register_verifier("zksnarkmerkle")
class SnarkMerkleProofVerifier(BaseVerifier):
    def __init__(self, setup_object=None):
        self.setup_object = setup_object

    def verify_proof(self, values, keys, root, proof, setup=None) -> bool:
        """
        Each Groth16 proof is checked against public inputs rebuilt from the
        caller's own root, keys and values; nothing the prover wrote is trusted.
        """
        proofs, _ = proof
        if not keys or len(keys) != len(values):
            return False
        expected_batches = -(-len(keys) // KEYS_BATCH_SIZE)
        if len(proofs) != expected_batches:
            return False
        worker = warm_up()
        for b, start in enumerate(range(0, len(keys), KEYS_BATCH_SIZE)):
            end = start + KEYS_BATCH_SIZE
            public = public_signals(root, keys[start:end], values[start:end])
            if not worker.verify(public, proofs[b]):
                return False
        return True
