from .pkg_importer import auto_import_submodules
import prover

class BaseProver:
    def generate_proof(self, tree, keys, setup=None):
        raise NotImplementedError

PROVER_REGISTRY = {}

def register_prover(name):
    def decorator(cls):
        PROVER_REGISTRY[name] = cls
        return cls
    return decorator

auto_import_submodules(prover)
