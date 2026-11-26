"""Transport to the pinned RISC Zero composite-STARK host.

Only the host performs receipt verification. The Python process never treats
a plain MPT witness check or a dev-mode receipt as a STARK proof.
"""

import json
import os
from pathlib import Path
import subprocess


HOST = Path(__file__).resolve().parent / "target" / "release" / "mpt_zkstark_host"


def _call(request: dict, timeout: int) -> dict:
    binary = os.environ.get("STARK_RISC0_HOST", str(HOST))
    result = subprocess.run(
        [binary],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
        env={**os.environ, "RISC0_DEV_MODE": "0", "RISC0_PROVER": "local"},
    )
    if result.returncode:
        raise RuntimeError("ZK-STARK host failed: " + result.stderr.strip()[-1000:])
    return json.loads(result.stdout)


def prove(nodes: list[bytes], root: bytes, key: bytes, value: bytes) -> bytes:
    if not isinstance(nodes, list) or not nodes or any(not isinstance(n, bytes) for n in nodes):
        raise ValueError("expected nonempty MPT witness")
    if not isinstance(root, bytes) or len(root) != 32 or not isinstance(key, bytes) or not isinstance(value, bytes):
        raise ValueError("invalid MPT statement")
    answer = _call({
        "action": "prove", "root": root.hex(), "key": key.hex(),
        "value": value.hex(), "nodes": [n.hex() for n in nodes],
    }, 7200)
    return bytes.fromhex(answer["proof"])


def verify(raw: bytes, root: bytes, key: bytes, value: bytes) -> bool:
    if not isinstance(raw, bytes) or not isinstance(root, bytes) or len(root) != 32 or not isinstance(key, bytes) or not isinstance(value, bytes):
        return False
    try:
        return _call({
            "action": "verify", "root": root.hex(), "key": key.hex(),
            "value": value.hex(), "proof": raw.hex(),
        }, 600) == {"valid": True}
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired):
        return False
