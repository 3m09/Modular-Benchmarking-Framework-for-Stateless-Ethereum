import importlib
import pkgutil
import pathlib

def auto_import_submodules(package):
    package_path = pathlib.Path(package.__file__).parent
    module_prefix = package.__name__ + "."

    for module_info in pkgutil.iter_modules([str(package_path)]):
        importlib.import_module(module_prefix + module_info.name)
