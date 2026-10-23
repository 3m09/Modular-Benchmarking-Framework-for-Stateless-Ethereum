from .pkg_importer import auto_import_submodules
import tree

class TreeNode:
    def __init__(self, width):
        self.width = width                       
        self.children = [None] * width           
        self.value = None  
        self.commitment_to_children = None
        self.type = 'non_leaf'  

        # --- NEW ATTRIBUTES FOR EIP-6800 ---
        self.stem = b''    # Stores the compressed path bytes (for Extension nodes)
        self.child = None  # Stores the single reference to the Suffix Tree                                         

class BaseTree:
    def __init__(self, width, db_path, hash_fn=None, setup_object=None):
        self.width = width
        self.db_path = db_path
        self.root = TreeNode(width)
        self.setup_object = setup_object
        self.hash_fn = hash_fn

    def insert(self, key, value):
        raise NotImplementedError

    def get_proof_tree(self, key):
        raise NotImplementedError
    
    def get(self, key):
        raise NotImplementedError
    

TREE_REGISTRY = {}

def register_tree(name):
    def decorator(cls):
        TREE_REGISTRY[name] = cls
        return cls
    return decorator

auto_import_submodules(tree)