# from registry.trees import BaseTree, register_tree
# from registry.trees import TreeNode
# from verkle.commitment_scheme import commit
# from verkle.hash_scheme import hash_point_to_field
# from verkle.utils.key_to_path import _key_to_path
# from verkle.serialization import serialize_verkle_node_flexible, deserialize_verkle_node_flexible, serialize_verkle_leaf_flexible, deserialize_verkle_leaf_flexible
# import plyvel, os
# import zlib

# @register_tree("verkle")
# class VerkleTree(BaseTree):

#     def __init__(self, width, db_path='./verkle', hash_fn=None, setup_object=None):
#         super().__init__(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup_object)
#         self.db = plyvel.DB(self.db_path + '/verkle_state_db', create_if_missing=True)
#         self._root_ref = open(self.db_path + '/verkle_root_ref.bin', 'rb').read() if os.path.exists(self.db_path + '/verkle_root_ref.bin') else None
#         if self._root_ref:
#             self.root = self._make_tree_node(self._root_ref)

#     def insert(self, key, value):
#         if not isinstance(key, (bytes, bytearray)):
#             raise TypeError("Key must be bytes or bytearray")
        
#         # value = int.from_bytes(value, byteorder='big')

#         path = _key_to_path(self.width, key)

#         node = self.root
#         stack = [node]

#         for i in range(len(path)-1):
#             if node.children[path[i]] is None:
#                 node = TreeNode(self.width)
#             else:
#                 node = self._make_tree_node(node.children[path[i]])
#             stack.append(node)

#         node.children[path[-1]] = value
#         node.type = 'leaf'

#         path_indices = path[:-1]

#         while stack:
#             current = stack.pop()
#             parent = stack[-1] if stack else None
#             # node = current
#             # if current.type == 'leaf':
#             #     print('found leaf node in the while loop:')
#             child_values = []
#             all_Child_none_flag = True
#             for child in current.children:
#                 if child is None:
#                     child_values.append(0)
#                 else:
#                     all_Child_none_flag = False
#                     child_values.append(int.from_bytes(child, byteorder='big'))
#             if all_Child_none_flag:
#                 print('all children are None, skipping commit')
            
#             # print("Committing at level with child values:", child_values)
#             current.commitment_to_children = commit(child_values, self.setup_object)
#             current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
#             self._store_node(current)
#             if parent:
#                 path_idx = path_indices.pop()
#                 parent.children[path_idx] = current.value
#             node = current

#         with open(self.db_path + '/verkle_root_ref.bin', 'wb') as f:
#             f.write(node.value)
#         self._root_ref = node.value
#         self.root = node

#     def get(self, key):
#         if not isinstance(key, (bytes, bytearray)):
#             raise TypeError("Key must be bytes or bytearray")

#         node = self.root
#         path = _key_to_path(self.width, key)

#         for i in range(len(path)-1):
#             if node.children[path[i]] is None:
#                 return None   
#             node = self._make_tree_node(node.children[path[i]])
            
#         node.type = 'leaf'

#         return int.from_bytes(node.children[path[-1]], byteorder='big')
    
#     def get_proof_tree(self, key):
#         if not isinstance(key, (bytes, bytearray)):
#             raise TypeError("Key must be bytes or bytearray")

#         proof = []
#         node = self.root
#         path = _key_to_path(self.width, key)
#         for i in range(len(path)-1):
#             if node.children[path[i]] is None:
#                 return None   
#             node = self._make_tree_node(node.children[path[i]])
#             proof.append(node.commitment_to_children)

#             # excluding the root and leaf commitments
#         return proof
    
#     def _store_node(self, node):
#         encoded = serialize_verkle_node_flexible(node.commitment_to_children, node.children)                               
#         reference = node.value          
#         self.db.put(reference, encoded)
#         return reference
    
#     def _make_tree_node(self, reference, type='non_leaf'):
#         data = self.db.get(reference)
#         if data is None:
#             raise KeyError("Node not found: " + reference.hex())
#         comm, child_hashes = deserialize_verkle_node_flexible(data)
#         node = TreeNode(self.width)
#         node.type = type
#         node.commitment_to_children = comm
#         node.value = hash_point_to_field(comm, self.setup_object.MODULUS).to_bytes(32, 'big')
#         if node.value != reference:
#             print('Warning: computed node reference does not match stored reference!')
#             print('Computed:', node.value.hex())
#             print('Stored:', reference.hex())
#         node.children = child_hashes
#         # print('printing commitment to children', comm)
#         return node


#     # def get_proof_size(self, commitments, final_commitment):
#     #     total_size = 0
#     #     # Serialize each list of intermediate commitments per key
#     #     for key_commitments in commitments:
#     #         print("key commitments length:", len(key_commitments))
#     #         for comm in key_commitments:
#     #             # Serialize each commitment (x, y) as bytes
#     #             data = bytearray()
#     #             x_int = int(comm[0])
#     #             y_int = int(comm[1])
                
#     #             # Calculate minimal byte length needed
#     #             x_len = (x_int.bit_length() + 7) // 8 or 1
#     #             y_len = (y_int.bit_length() + 7) // 8 or 1
                
#     #             x_bytes = x_int.to_bytes(x_len, 'big')
#     #             y_bytes = y_int.to_bytes(y_len, 'big')
                
#     #             data += x_bytes
#     #             data += y_bytes
#     #             total_size += len(data)
#     #     # Serialize the final commitment
#     #     data = bytearray()
#     #     x_int = int(final_commitment[0])
#     #     y_int = int(final_commitment[1])
        
#     #     # Calculate minimal byte length needed
#     #     x_len = (x_int.bit_length() + 7) // 8 or 1
#     #     y_len = (y_int.bit_length() + 7) // 8 or 1
        
#     #     x_bytes = x_int.to_bytes(x_len, 'big')
#     #     y_bytes = y_int.to_bytes(y_len, 'big')
        
#     #     data += x_bytes
#     #     data += y_bytes
#     #     total_size += len(data)
#     #     return total_size

#     def get_proof_size(self, commitments, final_commitment):
#         COMPRESSED_POINT_SIZE = 48
#         total_size = 0
        
#         for key_commitments in commitments:
#             # 48 bytes per compressed point
#             print(f"Depth: {len(key_commitments)}")
#             total_size += len(key_commitments) * COMPRESSED_POINT_SIZE
            
#         # Add the final commitment
#         total_size += COMPRESSED_POINT_SIZE 
        
#         return total_size

#     # def get_proof_size(self, commitments, keys) -> int:
#     #     COMPRESSED_POINT_SIZE = 48
#     #     VALUE_SIZE = 32
#     #     total_size = 0
        
#     #     # 1. Redundant intermediate commitments
#     #     for key_commitments in commitments:
#     #         total_size += len(key_commitments) * COMPRESSED_POINT_SIZE
            
#     #     # 2. The witness (final commitment)
#     #     total_size += COMPRESSED_POINT_SIZE 
        
#     #     # 3. The keys and values payload (Missing from your original)
#     #     total_size += len(keys) * VALUE_SIZE
#     #     total_size += len(keys) * 32  # Assuming 32-byte paths
        
#     #     return total_size





from registry.trees import TreeNode
from registry.trees import BaseTree, register_tree
from verkle.commitment_scheme import commit, commit_extension
from verkle.hash_scheme import hash_point_to_field
from verkle.serialization import (
    deserialize_any_node, 
    serialize_array_node,
    serialize_extension_node,
    PREFIX_INTERNAL,
    PREFIX_EXTENSION,
    PREFIX_SUFFIX
)
import plyvel, os
import math


@register_tree("verkle")
class VerkleTree(BaseTree):

    def __init__(self, width, db_path='./verkle', hash_fn=None, setup_object=None):
        super().__init__(width, db_path=db_path, hash_fn=hash_fn, setup_object=setup_object)
        self.db = plyvel.DB(self.db_path + '/verkle_state_db', create_if_missing=True)
        self._root_ref = open(self.db_path + '/verkle_root_ref.bin', 'rb').read() if os.path.exists(self.db_path + '/verkle_root_ref.bin') else None
        
        if self._root_ref:
            self.root = self._make_tree_node(self._root_ref)
        else:
            self.root = None

    def _get_key_chunks(self, key_bytes):
        """
        Splits a 256-bit (32-byte) key into chunks based on the tree width.
        For width=256, returns 32 chunks of 8 bits.
        For width=16, returns 64 chunks of 4 bits.
        """
        bits_per_chunk = int(math.log2(self.width))
        if 2 ** bits_per_chunk != self.width:
            raise ValueError("Tree width must be a power of 2.")
        
        key_int = int.from_bytes(key_bytes, 'big')
        total_bits = 256
        num_chunks = total_bits // bits_per_chunk
        
        chunks = []
        for i in range(num_chunks):
            # Shift down to get the target chunk, then mask it
            shift = total_bits - ((i + 1) * bits_per_chunk)
            mask = self.width - 1
            chunk = (key_int >> shift) & mask
            chunks.append(chunk)
            
        return tuple(chunks) # Using tuple so slices are hashable/immutable

    # -------------------------------------------------------------------
    # State Machine Insertion Logic (EIP-6800)
    # -------------------------------------------------------------------
    # def insert(self, key, value):
    #     if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
    #         raise TypeError("Key must be exactly 32 bytes for EIP-6800")
    #     if not isinstance(value, (bytes, bytearray)):
    #         value = value.to_bytes(32, byteorder='big') # Ensure value is bytes

    #     stem = key[:31]
    #     suffix = key[31]

    #     if self.root is None:
    #         self.root = TreeNode(self.width)
    #         self.root.type = 'internal'

    #     node = self.root
        
    #     # Stack stores tuples of: (parent_node, slot_in_parent, current_node)
    #     # slot_in_parent is an int (for internal nodes) or 'child' (for extension nodes)
    #     stack = [(None, None, node)] 
    #     depth = 0

    #     # Phase 1: Traversal and Node Splitting
    #     while True:
    #         if node.type == 'internal':
    #             current_byte = stem[depth]
    #             child_ref = node.children[current_byte]

    #             if child_ref is None:
    #                 # # Scenario A: Empty slot. Create Extension + Suffix Tree directly.
    #                 # suffix_tree = TreeNode(self.width)
    #                 # suffix_tree.type = 'suffix'
    #                 # suffix_tree.children[suffix] = value

    #                 # ext_node = TreeNode(self.width)
    #                 # ext_node.type = 'extension'
    #                 # ext_node.stem = stem[depth:] 

    #                 # Scenario A: Empty slot. Create Extension + Suffix Tree directly.
    #                 suffix_tree = TreeNode(self.width)
    #                 suffix_tree.type = 'suffix'
    #                 suffix_tree.children[suffix] = value

    #                 ext_node = TreeNode(self.width)
    #                 ext_node.type = 'extension'
                    
    #                 # --- THE FIX ---
    #                 ext_node.stem = stem[depth + 1:]
                    
    #                 stack.append((node, current_byte, ext_node))
    #                 stack.append((ext_node, 'child', suffix_tree))
    #                 break
    #             else:
    #                 # Scenario B: Traverse deeper
    #                 next_node = self._make_tree_node(child_ref)
    #                 stack.append((node, current_byte, next_node))
    #                 node = next_node
    #                 depth += 1

    #         # elif node.type == 'extension':
    #         #     existing_stem = node.stem
    #         #     new_stem = stem[depth:]

    #         #     if existing_stem == new_stem:
    #         #         # Stems match exactly. Just update the suffix tree.
    #         #         suffix_tree = self._make_tree_node(node.child)
    #         #         suffix_tree.children[suffix] = value
    #         #         stack.append((node, 'child', suffix_tree))
    #         #         break
    #         #     else:
    #         #         # COLLISION DETECTED: The stems diverge. 
    #         #         match_length = 0
    #         #         while (match_length < len(existing_stem) and 
    #         #                match_length < len(new_stem) and 
    #         #                existing_stem[match_length] == new_stem[match_length]):
    #         #             match_length += 1

    #         #         # 1. Create a new Internal Node at the point of divergence
    #         #         divergence_node = TreeNode(self.width)
    #         #         divergence_node.type = 'internal'

    #         #         # 2. Modify the old extension node to sit below the divergence
    #         #         old_diverge_byte = existing_stem[match_length]
    #         #         node.stem = existing_stem[match_length + 1:]
                    
    #         #         # 3. Create a new extension/suffix branch for the new key
    #         #         new_diverge_byte = new_stem[match_length]
    #         #         new_suffix_tree = TreeNode(self.width)
    #         #         new_suffix_tree.type = 'suffix'
    #         #         new_suffix_tree.children[suffix] = value

    #         #         new_ext_node = TreeNode(self.width)
    #         #         new_ext_node.type = 'extension'
    #         #         new_ext_node.stem = new_stem[match_length + 1:]

    #         #         # Note: We don't link DB references here, we link them in the Commit Phase below
    #         #         # We just modify the stack so the post-order traversal processes them correctly
                    
    #         #         # Replace the old extension node in the stack with the divergence node
    #         #         parent_node, slot_in_parent, _ = stack.pop()
    #         #         stack.append((parent_node, slot_in_parent, divergence_node))
                    
    #         #         # Add both branches to the stack to compute their commitments
    #         #         stack.append((divergence_node, old_diverge_byte, node))
    #         #         stack.append((divergence_node, new_diverge_byte, new_ext_node))
    #         #         stack.append((new_ext_node, 'child', new_suffix_tree))
    #         #         break
    #         elif node.type == 'extension':
    #             existing_stem = node.stem
    #             new_stem = stem[depth:]

    #             if existing_stem == new_stem:
    #                 # Stems match exactly. Just update the suffix tree.
    #                 suffix_tree = self._make_tree_node(node.child)
    #                 suffix_tree.children[suffix] = value
    #                 stack.append((node, 'child', suffix_tree))
    #                 break
    #             else:
    #                 # COLLISION DETECTED: The stems diverge. 
    #                 match_length = 0
    #                 while (match_length < len(existing_stem) and 
    #                        match_length < len(new_stem) and 
    #                        existing_stem[match_length] == new_stem[match_length]):
    #                     match_length += 1

    #                 # Remove the old extension node from the stack
    #                 parent_node, slot_in_parent, _ = stack.pop()
    #                 current_parent = parent_node
    #                 current_slot = slot_in_parent

    #                 # 1. Build a chain of Internal Nodes for the shared prefix
    #                 for i in range(match_length):
    #                     shared_internal = TreeNode(self.width)
    #                     shared_internal.type = 'internal'
    #                     shared_byte = existing_stem[i]
                        
    #                     stack.append((current_parent, current_slot, shared_internal))
    #                     current_parent = shared_internal
    #                     current_slot = shared_byte

    #                 # 2. Create the Divergence Node
    #                 divergence_node = TreeNode(self.width)
    #                 divergence_node.type = 'internal'
    #                 stack.append((current_parent, current_slot, divergence_node))

    #                 # 3. Modify the old extension node to sit below the divergence
    #                 old_diverge_byte = existing_stem[match_length]
    #                 node.stem = existing_stem[match_length + 1:]

    #                 # 4. Create a new extension/suffix branch for the new key
    #                 new_diverge_byte = new_stem[match_length]
    #                 new_suffix_tree = TreeNode(self.width)
    #                 new_suffix_tree.type = 'suffix'
    #                 new_suffix_tree.children[suffix] = value

    #                 new_ext_node = TreeNode(self.width)
    #                 new_ext_node.type = 'extension'
    #                 new_ext_node.stem = new_stem[match_length + 1:]

    #                 # 5. Link both branches to the divergence node
    #                 stack.append((divergence_node, old_diverge_byte, node))
    #                 stack.append((divergence_node, new_diverge_byte, new_ext_node))
    #                 stack.append((new_ext_node, 'child', new_suffix_tree))
    #                 break

    #         elif node.type == 'suffix':
    #             # Should not hit this in a standard EIP-6800 traversal unless pathing is wrong
    #             node.children[suffix] = value
    #             break

    #     # Phase 2: Commitment and Storage (Post-Order Traversal)
    #     while stack:
    #         parent, slot_in_parent, current = stack.pop()
            
    #         # Formulate child values for the polynomial commitment
    #         child_values = []
    #         if current.type == 'internal' or current.type == 'suffix':
    #             for child in current.children:
    #                 if child is None:
    #                     child_values.append(0)
    #                 else:
    #                     child_values.append(int.from_bytes(child, byteorder='big'))
            
    #         # elif current.type == 'extension':
    #         #     # Mapping the stem and child into a 256-wide array for the standard commit function
    #         #     # (A true Ethereum client uses a distinct polynomial for this, but mapping 
    #         #     #  allows your existing `commit` function to work mathematically).
    #         #     child_values = [0] * self.width
    #         #     for i, b in enumerate(current.stem):
    #         #         child_values[i] = b
    #         #     if current.child is not None:
    #         #         child_values[31] = int.from_bytes(current.child, byteorder='big')

    #         # # Calculate commitment and update DB value
    #         # current.commitment_to_children = commit(child_values, self.setup_object)
    #         # current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
            
    #         # Calculate commitment and update DB value
    #         if current.type == 'extension':
    #             # Use the mathematically correct EIP-6800 polynomial
    #             current.commitment_to_children = commit_extension(current.stem, current.child, self.setup_object)
    #         else:
    #             # Internal and Suffix nodes use the standard 256-wide array commit
    #             current.commitment_to_children = commit(child_values, self.setup_object)
                
    #         current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
    #         self._store_node(current)

    #         # Link this node's new DB reference to its parent
    #         if parent is not None:
    #             if slot_in_parent == 'child':
    #                 parent.child = current.value
    #             else:
    #                 parent.children[slot_in_parent] = current.value
    #         else:
    #             # We reached the root
    #             self.root = current

    #     with open(self.db_path + '/verkle_root_ref.bin', 'wb') as f:
    #         f.write(self.root.value)
    #     self._root_ref = self.root.value

    def insert(self, key, value):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise TypeError("Key must be exactly 32 bytes")
        if not isinstance(value, (bytes, bytearray)):
            value = value.to_bytes(32, byteorder='big')

        # --- MODIFIED: Dynamic key chunking ---
        chunks = self._get_key_chunks(key)
        stem = chunks[:-1]    # All chunks except the last
        suffix = chunks[-1]   # The final chunk acts as the suffix

        if self.root is None:
            self.root = TreeNode(self.width)
            self.root.type = 'internal'

        node = self.root
        stack = [(None, None, node)] 
        depth = 0

        while True:
            if node.type == 'internal':
                current_chunk = stem[depth] # MODIFIED
                child_ref = node.children[current_chunk]

                if child_ref is None:
                    suffix_tree = TreeNode(self.width)
                    suffix_tree.type = 'suffix'
                    suffix_tree.children[suffix] = value

                    ext_node = TreeNode(self.width)
                    ext_node.type = 'extension'
                    ext_node.stem = stem[depth + 1:]
                    
                    stack.append((node, current_chunk, ext_node))
                    stack.append((ext_node, 'child', suffix_tree))
                    break
                else:
                    next_node = self._make_tree_node(child_ref)
                    stack.append((node, current_chunk, next_node))
                    node = next_node
                    depth += 1

            elif node.type == 'extension':
                existing_stem = node.stem
                new_stem = stem[depth:]

                if existing_stem == new_stem:
                    suffix_tree = self._make_tree_node(node.child)
                    suffix_tree.children[suffix] = value
                    stack.append((node, 'child', suffix_tree))
                    break
                else:
                    match_length = 0
                    while (match_length < len(existing_stem) and 
                           match_length < len(new_stem) and 
                           existing_stem[match_length] == new_stem[match_length]):
                        match_length += 1

                    parent_node, slot_in_parent, _ = stack.pop()
                    current_parent = parent_node
                    current_slot = slot_in_parent

                    for i in range(match_length):
                        shared_internal = TreeNode(self.width)
                        shared_internal.type = 'internal'
                        shared_chunk = existing_stem[i] # MODIFIED
                        
                        stack.append((current_parent, current_slot, shared_internal))
                        current_parent = shared_internal
                        current_slot = shared_chunk

                    divergence_node = TreeNode(self.width)
                    divergence_node.type = 'internal'
                    stack.append((current_parent, current_slot, divergence_node))

                    old_diverge_chunk = existing_stem[match_length] # MODIFIED
                    node.stem = existing_stem[match_length + 1:]

                    new_diverge_chunk = new_stem[match_length] # MODIFIED
                    new_suffix_tree = TreeNode(self.width)
                    new_suffix_tree.type = 'suffix'
                    new_suffix_tree.children[suffix] = value

                    new_ext_node = TreeNode(self.width)
                    new_ext_node.type = 'extension'
                    new_ext_node.stem = new_stem[match_length + 1:]

                    stack.append((divergence_node, old_diverge_chunk, node))
                    stack.append((divergence_node, new_diverge_chunk, new_ext_node))
                    stack.append((new_ext_node, 'child', new_suffix_tree))
                    break

            elif node.type == 'suffix':
                node.children[suffix] = value
                break

        # Phase 2: Commitment and Storage (Post-Order Traversal)
        while stack:
            parent, slot_in_parent, current = stack.pop()
            
            child_values = []
            if current.type == 'internal' or current.type == 'suffix':
                for child in current.children:
                    if child is None:
                        child_values.append(0)
                    else:
                        child_values.append(int.from_bytes(child, byteorder='big'))
            
            if current.type == 'extension':
                # NOTE: Ensure your commit_extension handles tuples of ints instead of bytes!
                current.commitment_to_children = commit_extension(current.stem, current.child, self.setup_object)
            else:
                # NOTE: Ensure self.setup_object is large enough to handle an array of `self.width`
                current.commitment_to_children = commit(child_values, self.setup_object)
                
            current.value = hash_point_to_field(current.commitment_to_children, self.setup_object.MODULUS).to_bytes(32, 'big')
            self._store_node(current)

            if parent is not None:
                if slot_in_parent == 'child':
                    parent.child = current.value
                else:
                    parent.children[slot_in_parent] = current.value
            else:
                self.root = current

        with open(self.db_path + '/verkle_root_ref.bin', 'wb') as f:
            f.write(self.root.value)
        self._root_ref = self.root.value

    # -------------------------------------------------------------------
    # Retrieval Logic
    # -------------------------------------------------------------------
    # def get(self, key):
    #     if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
    #         raise TypeError("Key must be exactly 32 bytes")

    #     stem = key[:31]
    #     suffix = key[31]

    #     node = self.root
    #     depth = 0

    #     while node is not None:
    #         if node.type == 'internal':
    #             current_byte = stem[depth]
    #             child_ref = node.children[current_byte]
    #             if child_ref is None:
    #                 return None
    #             node = self._make_tree_node(child_ref)
    #             depth += 1
                
    #         elif node.type == 'extension':
    #             if stem[depth:] == node.stem:
    #                 node = self._make_tree_node(node.child)
    #             else:
    #                 return None # Stem mismatch
                    
    #         elif node.type == 'suffix':
    #             val_bytes = node.children[suffix]
    #             if val_bytes is None:
    #                 return None
    #             return int.from_bytes(val_bytes, byteorder='big')
                
    #     return None

    def get(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise TypeError("Key must be exactly 32 bytes")

        # --- MODIFIED ---
        chunks = self._get_key_chunks(key)
        stem = chunks[:-1]
        suffix = chunks[-1]

        node = self.root
        depth = 0

        while node is not None:
            if node.type == 'internal':
                current_chunk = stem[depth]
                child_ref = node.children[current_chunk]
                if child_ref is None:
                    return None
                node = self._make_tree_node(child_ref)
                depth += 1
                
            elif node.type == 'extension':
                if stem[depth:] == node.stem:
                    node = self._make_tree_node(node.child)
                else:
                    return None 
                    
            elif node.type == 'suffix':
                val_bytes = node.children[suffix]
                if val_bytes is None:
                    return None
                return int.from_bytes(val_bytes, byteorder='big')
                
        return None
    
    # def get_proof_tree(self, key):
    #     if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
    #         raise TypeError("Key must be exactly 32 bytes")

    #     stem = key[:31]
    #     suffix = key[31]

    #     proof = []
    #     node = self.root
    #     depth = 0

    #     while node is not None:
    #         proof.append(node.commitment_to_children)
            
    #         if node.type == 'internal':
    #             current_byte = stem[depth]
    #             child_ref = node.children[current_byte]
    #             if child_ref is None:
    #                 return None
    #             node = self._make_tree_node(child_ref)
    #             depth += 1
                
    #         elif node.type == 'extension':
    #             if stem[depth:] == node.stem:
    #                 node = self._make_tree_node(node.child)
    #             else:
    #                 return None
                    
    #         elif node.type == 'suffix':
    #             return proof
                
    #     return None

    # def get_proof_tree(self, key):
    #     if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
    #         raise TypeError("Key must be exactly 32 bytes")

    #     stem = key[:31]
    #     suffix = key[31]

    #     proof = []
    #     node = self.root
    #     depth = 0

    #     while node is not None:
    #         proof.append(node.commitment_to_children)
    #         if node.type == 'internal':
    #             current_byte = stem[depth]
    #             child_ref = node.children[current_byte]
    #             if child_ref is None:
    #                 # Return partial proof instead of None
    #                 return proof[1:] 
    #             node = self._make_tree_node(child_ref)
    #             depth += 1
                
    #         elif node.type == 'extension':
    #             if stem[depth:] == node.stem:
    #                 node = self._make_tree_node(node.child)
    #             else:
    #                 # Return partial proof instead of None
    #                 return proof[1:]
                    
    #         elif node.type == 'suffix':
    #             # Suffix reached, proof is complete
    #             return proof[1:]
                
    #     # Fallback return
    #     return proof[1:] if len(proof) > 1 else []
    
    def get_proof_tree(self, key):
        if not isinstance(key, (bytes, bytearray)) or len(key) != 32:
            raise TypeError("Key must be exactly 32 bytes")

        # --- MODIFIED ---
        chunks = self._get_key_chunks(key)
        stem = chunks[:-1]
        suffix = chunks[-1]

        proof = []
        node = self.root
        depth = 0

        while node is not None:
            proof.append(node.commitment_to_children)
            
            if node.type == 'internal':
                current_chunk = stem[depth]
                child_ref = node.children[current_chunk]
                if child_ref is None:
                    return proof[1:] 
                node = self._make_tree_node(child_ref)
                depth += 1
                
            elif node.type == 'extension':
                if stem[depth:] == node.stem:
                    node = self._make_tree_node(node.child)
                else:
                    return proof[1:]
                    
            elif node.type == 'suffix':
                return proof[1:]
                
        return proof[1:] if len(proof) > 1 else []
    
    # -------------------------------------------------------------------
    # Storage and Deserialization Routing
    # -------------------------------------------------------------------
    def _store_node(self, node):
        if node.type == 'internal':
            encoded = serialize_array_node(PREFIX_INTERNAL, node.commitment_to_children, node.children)
        elif node.type == 'suffix':
            encoded = serialize_array_node(PREFIX_SUFFIX, node.commitment_to_children, node.children)
        elif node.type == 'extension':
            # encoded = serialize_extension_node(node.commitment_to_children, node.stem, node.child)
            stem_bytes = bytes(node.stem)
            encoded = serialize_extension_node(node.commitment_to_children, stem_bytes, node.child)
            
        reference = node.value          
        self.db.put(reference, encoded)
        return reference
    
    def _make_tree_node(self, reference):
        data = self.db.get(reference)
        if data is None:
            raise KeyError("Node not found in DB: " + reference.hex())
            
        # The router returns the prefix flag, the commitment, and the node-specific payload
        result = deserialize_any_node(data)
        prefix = result[0]
        comm = result[1]
        
        node = TreeNode(self.width)
        node.commitment_to_children = comm
        node.value = hash_point_to_field(comm, self.setup_object.MODULUS).to_bytes(32, 'big')
        
        if node.value != reference:
            print('Warning: computed node reference does not match stored reference!')
        
        if prefix == PREFIX_INTERNAL or prefix == PREFIX_SUFFIX:
            node.type = 'internal' if prefix == PREFIX_INTERNAL else 'suffix'
            node.children = result[2]
        elif prefix == PREFIX_EXTENSION:
            node.type = 'extension'
            # node.stem = result[2]
            # node.child = result[3]
            node.stem = tuple(result[2]) 
            node.child = result[3]
            
        return node

    # -------------------------------------------------------------------
    # Metrics
    # -------------------------------------------------------------------
    def get_proof_size(self, commitments, final_commitment):
        COMPRESSED_POINT_SIZE = 48
        total_size = 0
        
        for key_commitments in commitments:
            # 48 bytes per compressed point
            total_size += len(key_commitments) * COMPRESSED_POINT_SIZE
            
        # Add the final commitment
        total_size += COMPRESSED_POINT_SIZE 
        
        return total_size