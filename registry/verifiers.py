from .pkg_importer import auto_import_submodules
import verifier

class BaseVerifier:
    def verify_proof(self, values, root, proof, keys, setup=None):
        raise NotImplementedError

VERIFIER_REGISTRY = {}

def register_verifier(name):
    def decorator(cls):
        VERIFIER_REGISTRY[name] = cls
        return cls
    return decorator

auto_import_submodules(verifier)