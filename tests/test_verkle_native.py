"""The native (blst) Verkle backend must match the py_ecc reference exactly."""
import json
import tempfile

import pytest

from registry.provers import PROVER_REGISTRY
from registry.setup import SETUP_REGISTRY
from registry.trees import TREE_REGISTRY
from registry.verifiers import VERIFIER_REGISTRY
from verkle.eip6800 import account_to_leaves
from verkle.native_bls import g1_compress

SECRET = 1927409816240961209460912649124


@pytest.fixture(scope="module")
def statement():
    setup = SETUP_REGISTRY["verkle_kzg"](SECRET, 16)
    tree = TREE_REGISTRY["verkle_eip6800"](16, db_path=tempfile.mkdtemp(), hash_fn="", setup_object=setup)
    accounts = [(bytes.fromhex(k[2:]), bytes.fromhex(v[2:]))
                for k, v in list(json.load(open("data.json")).items())[:24]]
    pairs = []
    for key, value in accounts:
        stem, leaves = account_to_leaves(key, value)
        tree.insert_stem(stem, leaves)
        pairs += [(stem + bytes([s]), v) for s, v in sorted(leaves.items())]
    keys, values = [k for k, _ in pairs[:6]], [v for _, v in pairs[:6]]
    return setup, tree, keys, values


def test_native_witness_matches_reference(statement):
    setup, tree, keys, _ = statement
    ref_commitments, ref_witness = PROVER_REGISTRY["verkle_eip6800_pyecc"](setup).generate_proof(tree, keys)
    commitments, witness = PROVER_REGISTRY["verkle_eip6800"](setup).generate_proof(tree, keys)
    assert commitments == ref_commitments
    assert witness == g1_compress(ref_witness)


def test_native_verifier_accepts_and_rejects(statement):
    setup, tree, keys, values = statement
    root = tree.root.commitment_to_children
    proof = PROVER_REGISTRY["verkle_eip6800"](setup).generate_proof(tree, keys)
    verifier = VERIFIER_REGISTRY["verkle_eip6800"](setup)
    assert verifier.verify_proof(values, keys, root, proof)
    tampered = [values[0][:-1] + bytes([values[0][-1] ^ 1])] + values[1:]
    with pytest.raises(AssertionError):
        verifier.verify_proof(tampered, keys, root, proof)
