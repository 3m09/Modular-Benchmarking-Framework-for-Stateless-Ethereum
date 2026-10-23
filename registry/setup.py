from .pkg_importer import auto_import_submodules
import setups

class BaseSetup:
    def __init__(self, security_parameter):
        self.security_parameter = security_parameter
    
SETUP_REGISTRY = {}

def register_setup(name):
    def decorator(cls):
        SETUP_REGISTRY[name] = cls
        return cls
    return decorator

auto_import_submodules(setups)