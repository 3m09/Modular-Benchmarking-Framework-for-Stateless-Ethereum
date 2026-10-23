from merkle.node import Node
from merkle.nibble_path import NibblePath

# def _zk_encode(node): # Remove 'self' in the prover script
#     """Canonical 32-byte aligned ZK serialization"""
#     if isinstance(node, Node.Leaf):
#         path_bytes = node.path.encode(is_leaf=True)
#         safe_data = node.data if node.data else b''
#         # === DEBUG INJECTION START ===
#         print(f"\n--- ENCODE DEBUG (LEAF) ---")
#         print(f"1. Nibble length: {len(node.path)}")
#         print(f"2. path_bytes length (bytes): {len(path_bytes)}")
#         if len(path_bytes) > 32:
#             print("   >>> WARNING: path_bytes exceeds 32 bytes! <<<")
#         # === DEBUG INJECTION END ===
#         return (
#             (1).to_bytes(32, 'big') +                               # Chunk 0
#             len(path_bytes).to_bytes(32, 'big') +                   # Chunk 1
#             path_bytes.ljust(32, b'\0') +                           # Chunk 2
#             len(safe_data).to_bytes(32, 'big') +                    # Chunk 3
#             safe_data.ljust(32, b'\0')                              # Chunk 4
#         )
        
#     elif isinstance(node, Node.Extension):
#         path_bytes = node.path.encode(is_leaf=False)
#         return (
#             (2).to_bytes(32, 'big') +                               # Chunk 0
#             len(path_bytes).to_bytes(32, 'big') +                   # Chunk 1
#             path_bytes.ljust(32, b'\0') +                           # Chunk 2
#             node.next_ref                                           # Chunk 3
#         )
        
#     elif isinstance(node, Node.Branch):
#         res = (3).to_bytes(32, 'big')                               # Chunk 0
#         for b in node.branches:
#             res += b if b else b'\0'*32                             # Chunks 1-16
#         safe_data = node.data if node.data else b''
#         res += len(safe_data).to_bytes(32, 'big')                   # Chunk 17
#         res += safe_data.ljust(32, b'\0')                           # Chunk 18
#         return res
        
#     raise TypeError("Unknown node type")

# def _zk_decode(data): # Remove 'self' in the prover script
#     """Deserialize recognizing exact 32-byte boundaries"""
#     node_type = int.from_bytes(data[:32], 'big')
    
#     if node_type == 1:
#         path_len = int.from_bytes(data[32:64], 'big')
#         path_bytes = data[64 : 64 + path_len]
#         path, _ = NibblePath.decode_with_type(path_bytes)
        
#         data_len = int.from_bytes(data[96:128], 'big')
#         data_val = data[128 : 128 + data_len]
#         return Node.Leaf(path, data_val)
        
#     elif node_type == 2:
#         path_len = int.from_bytes(data[32:64], 'big')
#         path_bytes = data[64 : 64 + path_len]
#         path, _ = NibblePath.decode_with_type(path_bytes)
        
#         next_ref = data[96:128] 
#         return Node.Extension(path, next_ref)
        
#     elif node_type == 3:
#         branches = []
#         for i in range(16):
#             b_bytes = data[32 + (i * 32) : 64 + (i * 32)]
#             branches.append(b_bytes if b_bytes != b'\0'*32 else b'')
            
#         data_len = int.from_bytes(data[544:576], 'big')
#         data_val = data[576 : 576 + data_len]
#         return Node.Branch(branches, data_val)
        
#     raise ValueError(f"Unknown ZK node type: {node_type}")

# def _zk_encode(node):
#     """Canonical 32-byte aligned ZK serialization"""
#     if isinstance(node, Node.Leaf):
#         path_bytes = node.path.encode(is_leaf=True)
#         safe_data = node.data if node.data else b''
#         return (
#             (1).to_bytes(32, 'big') +                               # Chunk 0: Type
#             len(path_bytes).to_bytes(32, 'big') +                   # Chunk 1: Path Len
#             path_bytes.ljust(64, b'\0') +                           # Chunks 2 & 3: Path (64 bytes)
#             len(safe_data).to_bytes(32, 'big') +                    # Chunk 4: Data Len
#             safe_data.ljust(32, b'\0')                              # Chunk 5: Data Val
#         )
        
#     elif isinstance(node, Node.Extension):
#         path_bytes = node.path.encode(is_leaf=False)
#         return (
#             (2).to_bytes(32, 'big') +                               # Chunk 0: Type
#             len(path_bytes).to_bytes(32, 'big') +                   # Chunk 1: Path Len
#             path_bytes.ljust(64, b'\0') +                           # Chunks 2 & 3: Path (64 bytes)
#             node.next_ref                                           # Chunk 4: Next Ref
#         )
        
#     elif isinstance(node, Node.Branch):
#         res = (3).to_bytes(32, 'big')                               # Chunk 0
#         for b in node.branches:
#             res += b if b else b'\0'*32                             # Chunks 1-16
#         safe_data = node.data if node.data else b''
#         res += len(safe_data).to_bytes(32, 'big')                   # Chunk 17
#         res += safe_data.ljust(32, b'\0')                           # Chunk 18
#         return res
        
#     raise TypeError("Unknown node type")

def _zk_encode(node):
    """Canonical 32-byte aligned ZK serialization"""
    if isinstance(node, Node.Leaf):
        path_bytes = node.path.encode(is_leaf=True)
        safe_data = node.data if node.data else b''
        return (
            (1).to_bytes(32, 'big') +                               
            len(path_bytes).to_bytes(32, 'big') +                   
            path_bytes.ljust(64, b'\0') +                           
            len(safe_data).to_bytes(32, 'big') +                    
            # Expanded to 3 chunks (96 bytes) to hold ETH State
            safe_data.ljust(96, b'\0')                              
        )
        
    elif isinstance(node, Node.Extension):
        # Extension nodes don't hold data, no change needed here
        path_bytes = node.path.encode(is_leaf=False)
        return (
            (2).to_bytes(32, 'big') +                               
            len(path_bytes).to_bytes(32, 'big') +                   
            path_bytes.ljust(64, b'\0') +                           
            node.next_ref                                           
        )
        
    elif isinstance(node, Node.Branch):
        res = (3).to_bytes(32, 'big')                               
        for b in node.branches:
            res += b if b else b'\0'*32                             
        safe_data = node.data if node.data else b''
        res += len(safe_data).to_bytes(32, 'big')                   
        # Expanded to 3 chunks (96 bytes)
        res += safe_data.ljust(96, b'\0')                           
        return res
        
    raise TypeError("Unknown node type")

def _zk_decode(data):
    """Deserialize recognizing exact 32-byte boundaries"""
    node_type = int.from_bytes(data[:32], 'big')
    
    if node_type == 1:
        path_len = int.from_bytes(data[32:64], 'big')
        path_bytes = data[64 : 64 + path_len]
        path, _ = NibblePath.decode_with_type(path_bytes)
        
        # Shifted +32 bytes to account for the new 64-byte path
        data_len = int.from_bytes(data[128:160], 'big') 
        data_val = data[160 : 160 + data_len]
        return Node.Leaf(path, data_val)
        
    elif node_type == 2:
        path_len = int.from_bytes(data[32:64], 'big')
        path_bytes = data[64 : 64 + path_len]
        path, _ = NibblePath.decode_with_type(path_bytes)
        
        # Shifted +32 bytes
        next_ref = data[128:160] 
        return Node.Extension(path, next_ref)
        
    elif node_type == 3:
        branches = []
        for i in range(16):
            b_bytes = data[32 + (i * 32) : 64 + (i * 32)]
            branches.append(b_bytes if b_bytes != b'\0'*32 else b'')
            
        data_len = int.from_bytes(data[544:576], 'big')
        data_val = data[576 : 576 + data_len]
        return Node.Branch(branches, data_val)
        
    raise ValueError(f"Unknown ZK node type: {node_type}")