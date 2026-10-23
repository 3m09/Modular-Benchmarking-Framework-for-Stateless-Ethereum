import rlp
from .nibble_path import NibblePath
from .hash import keccak_hash, poseidon_hash_bytes


def _prepare_reference_for_usage(ref):
    """ Encodes reference into RLP if needed so stored references will appear as bytes. """
    if isinstance(ref, list):
        return rlp.encode(ref)

    return ref


def _prepare_reference_for_encoding(ref):
    """ Decodes RLP-encoded reference if needed so the full node will be encoded correctly. """
    if 0 < len(ref) < 32:
        return rlp.decode(ref)

    return ref

def _hash_data(data: bytes, hash_fn: str = "keccak") -> bytes:
    if hash_fn == "keccak":
        return keccak_hash(data)
    if hash_fn == "poseidon":
        return poseidon_hash_bytes(data)
    raise ValueError("hash_fn must be 'keccak' or 'poseidon'")



class Node:
    EMPTY_HASH = keccak_hash(rlp.encode(b''))

    @staticmethod
    def empty_hash(hash_fn: str = "keccak") -> bytes:
        return _hash_data(rlp.encode(b''), hash_fn)

    class Leaf:
        def __init__(self, path, data):
            self.path = path
            self.data = data

        def encode(self):
            return rlp.encode([self.path.encode(True), self.data])

    class Extension:
        def __init__(self, path, next_ref):
            self.path = path
            self.next_ref = next_ref

        def encode(self):
            next_ref = _prepare_reference_for_encoding(self.next_ref)
            return rlp.encode([self.path.encode(False), next_ref])

    class Branch:
        def __init__(self, branches, data=None):
            self.branches = branches
            self.data = data

        def encode(self):
            branches = list(map(_prepare_reference_for_encoding, self.branches))
            return rlp.encode(branches + [self.data])

    def decode(encoded_data):
        """ Decodes node from RLP. """
        data = rlp.decode(encoded_data)

        # Branch has (width + 1) entries; Leaf/Extension have 2
        if len(data) == 2:
            path, is_leaf = NibblePath.decode_with_type(data[0])
            if is_leaf:
                return Node.Leaf(path, data[1])
            else:
                ref = _prepare_reference_for_usage(data[1])
                return Node.Extension(path, ref)

        if len(data) < 3:
            raise ValueError("Invalid RLP node length")

        branches = list(map(_prepare_reference_for_usage, data[:-1]))
        node_data = data[-1]
        return Node.Branch(branches, node_data)

    def into_reference(node, hash_fn: str = "keccak"):
        """
        Returns reference to the given node.

        If length of encoded node is less than 32 bytes, the reference is encoded node itself (In-place reference).
        Otherwise reference is hash of encoded node.
        """
        encoded_node = node.encode()
        if len(encoded_node) < 32:
            return encoded_node
        else:
            return _hash_data(encoded_node, hash_fn)
    
    @staticmethod
    def into_reference_from_encoded(encoded_node: bytes, hash_fn: str = "keccak"):
        """
        Given an encoded node, return what its reference should be.
        - If encoded node is >= 32 bytes: hash it
        - Otherwise: return the encoded bytes directly (inline)
        """
        if len(encoded_node) >= 32:
            return _hash_data(encoded_node, hash_fn)
        else:
            return encoded_node

# import rlp
# from .nibble_path import NibblePath
# from .hash import keccak_hash, poseidon_hash_bytes

# # Import your custom ZK serialization module
# from zkSNARK.zk_encoder_decoder import _zk_encode, _zk_decode


# def _prepare_reference_for_usage(ref):
#     """ Encodes reference into RLP if needed so stored references will appear as bytes. """
#     if isinstance(ref, list):
#         return rlp.encode(ref)
#     return ref


# def _prepare_reference_for_encoding(ref):
#     """ Decodes RLP-encoded reference if needed so the full node will be encoded correctly. """
#     if 0 < len(ref) < 32:
#         return rlp.decode(ref)
#     return ref


# def _hash_data(data: bytes, hash_fn: str = "keccak") -> bytes:
#     if hash_fn == "keccak":
#         return keccak_hash(data)
#     if hash_fn == "poseidon":
#         return poseidon_hash_bytes(data)
#     raise ValueError("hash_fn must be 'keccak' or 'poseidon'")


# class Node:
#     EMPTY_HASH = keccak_hash(rlp.encode(b''))

#     @staticmethod
#     def empty_hash(hash_fn: str = "keccak") -> bytes:
#         # Note: If ZK circuits need a specific 32-byte empty hash representation, 
#         # you may want to override this specifically for "poseidon" in the future.
#         return _hash_data(rlp.encode(b''), hash_fn)

#     class Leaf:
#         def __init__(self, path, data):
#             self.path = path
#             self.data = data

#         def encode(self, hash_fn: str = "keccak"):
#             if hash_fn == "poseidon":
#                 return _zk_encode(self)
#             return rlp.encode([self.path.encode(True), self.data])

#     class Extension:
#         def __init__(self, path, next_ref):
#             self.path = path
#             self.next_ref = next_ref

#         def encode(self, hash_fn: str = "keccak"):
#             if hash_fn == "poseidon":
#                 return _zk_encode(self)
            
#             next_ref = _prepare_reference_for_encoding(self.next_ref)
#             return rlp.encode([self.path.encode(False), next_ref])

#     class Branch:
#         def __init__(self, branches, data=None):
#             self.branches = branches
#             self.data = data

#         def encode(self, hash_fn: str = "keccak"):
#             if hash_fn == "poseidon":
#                 return _zk_encode(self)
            
#             branches = list(map(_prepare_reference_for_encoding, self.branches))
#             return rlp.encode(branches + [self.data])

#     @staticmethod
#     def decode(encoded_data, hash_fn: str = "keccak"):
#         """ Decodes node based on the hashing context. """
        
#         # Divert completely to ZK decoding to bypass RLP
#         if hash_fn == "poseidon":
#             return _zk_decode(encoded_data)
            
#         data = rlp.decode(encoded_data)

#         # Branch has (width + 1) entries; Leaf/Extension have 2
#         if len(data) == 2:
#             path, is_leaf = NibblePath.decode_with_type(data[0])
#             if is_leaf:
#                 return Node.Leaf(path, data[1])
#             else:
#                 ref = _prepare_reference_for_usage(data[1])
#                 return Node.Extension(path, ref)

#         if len(data) < 3:
#             raise ValueError("Invalid RLP node length")

#         branches = list(map(_prepare_reference_for_usage, data[:-1]))
#         node_data = data[-1]
#         return Node.Branch(branches, node_data)

#     @staticmethod
#     def into_reference(node, hash_fn: str = "keccak"):
#         """
#         Returns reference to the given node.

#         If length of encoded node is less than 32 bytes, the reference is the 
#         encoded node itself (In-place reference). Otherwise reference is the 
#         hash of the encoded node.
#         """
#         # Pass the hash_fn down to ensure the correct encoding method is used
#         encoded_node = node.encode(hash_fn)
        
#         if len(encoded_node) < 32:
#             return encoded_node
#         else:
#             return _hash_data(encoded_node, hash_fn)
    
#     @staticmethod
#     def into_reference_from_encoded(encoded_node: bytes, hash_fn: str = "keccak"):
#         """
#         Given an encoded node, return what its reference should be.
#         - If encoded node is >= 32 bytes: hash it
#         - Otherwise: return the encoded bytes directly (inline)
#         """
#         if len(encoded_node) >= 32:
#             return _hash_data(encoded_node, hash_fn)
#         else:
#             return encoded_node