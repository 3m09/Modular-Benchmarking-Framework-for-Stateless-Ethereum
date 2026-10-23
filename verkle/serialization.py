import zlib
from py_ecc import optimized_bls12_381 as b

# # from typeguard import value

PREFIX_INTERNAL = b'\x00'
PREFIX_EXTENSION = b'\x01'
PREFIX_SUFFIX = b'\x02'

def serialize_array_node(node_type_prefix, node_commitment, child_hashes):
    """
    node_commitment: tuple(x, y) 2D point
    child_hashes: list of bytes or None
    """
    data = bytearray()
    x_int = int(node_commitment[0])
    y_int = int(node_commitment[1])
    
    # Calculate minimal byte length needed
    x_len = (x_int.bit_length() + 7) // 8 or 1
    y_len = (y_int.bit_length() + 7) // 8 or 1
    
    x_bytes = x_int.to_bytes(x_len, 'big')
    y_bytes = y_int.to_bytes(y_len, 'big')
    
    data += node_type_prefix # \x00 or \x02
    data += x_len.to_bytes(1, 'big')  # store x length
    data += x_bytes
    data += y_len.to_bytes(1, 'big')  # store y length
    data += y_bytes
    
    bf = len(child_hashes)
    data += bf.to_bytes(2, 'big')

    # 3. Build bitmap for existing children
    bitmap_bytes = (bf + 7) // 8
    bitmap = bytearray(bitmap_bytes)
    child_data = b""
    for i, h in enumerate(child_hashes):
        if h is not None:
            byte_idx = i // 8
            bit_idx = i % 8
            bitmap[byte_idx] |= (1 << bit_idx)
            child_data += h
    data += bytes(bitmap)
    data += child_data
    
    return zlib.compress(data, level=3)

# def serialize_verkle_leaf_flexible(node_commitment, value):
#     """
#     node_commitment: tuple(x, y) 2D point
#     value: bytes
#     """
#     data = bytearray()
#     x_int = int(node_commitment[0])
#     y_int = int(node_commitment[1])
    
#     # Calculate minimal byte length needed
#     x_len = (x_int.bit_length() + 7) // 8 or 1
#     y_len = (y_int.bit_length() + 7) // 8 or 1
#     val_len = (value.bit_length() + 7) // 8 or 1
    
#     x_bytes = x_int.to_bytes(x_len, 'big')
#     y_bytes = y_int.to_bytes(y_len, 'big')

#     data += b'\x01'  # leaf node prefix
#     data += x_len.to_bytes(1, 'big')  # store x length
#     data += x_bytes
#     data += y_len.to_bytes(1, 'big')  # store y length
#     data += y_bytes
#     data += val_len.to_bytes(4, 'big')
#     data += value.to_bytes(val_len, 'big')

#     return zlib.compress(data, level=3)

# # def deserialize_verkle_node_flexible(serialized):
# #     data = zlib.decompress(serialized)
# #     idx = 0
    
# #     x_len = data[idx]
# #     idx += 1
# #     x = int.from_bytes(data[idx:idx+x_len], 'big')
# #     idx += x_len
    
# #     y_len = data[idx]
# #     idx += 1
# #     y = int.from_bytes(data[idx:idx+y_len], 'big')
# #     idx += y_len
    
# #     commitment = (b.FQ(x), b.FQ(y))

# #     bf = int.from_bytes(data[idx:idx+2], 'big')
# #     idx += 2

# #     bitmap_bytes = (bf + 7) // 8
# #     bitmap = data[idx:idx+bitmap_bytes]
# #     idx += bitmap_bytes

# #     child_hashes = []
# #     for i in range(bf):
# #         byte_idx = i // 8
# #         bit_idx = i % 8
# #         if (bitmap[byte_idx] >> bit_idx) & 1:
# #             child_hashes.append(data[idx:idx+32])
# #             idx += 32
# #         else:
# #             child_hashes.append(None)

# #     return commitment, child_hashes

# # def deserialize_verkle_leaf_flexible(serialized):
# #     data = zlib.decompress(serialized)
# #     idx = 1
    
# #     x_len = data[idx]
# #     idx += 1
# #     x = int.from_bytes(data[idx:idx+x_len], 'big')
# #     idx += x_len
    
# #     y_len = data[idx]
# #     idx += 1
# #     y = int.from_bytes(data[idx:idx+y_len], 'big')
# #     idx += y_len
    
# #     commitment = (x, y)
    
# #     length = int.from_bytes(data[idx:idx+4], 'big')
# #     idx += 4
# #     value = data[idx:idx+length]
    
# #     return commitment, int.from_bytes(value, 'big')

def serialize_extension_node(node_commitment, stem: bytes, child_hash: bytes):
    data = bytearray()
    x_int = int(node_commitment[0])
    y_int = int(node_commitment[1])
    
    x_len = (x_int.bit_length() + 7) // 8 or 1
    y_len = (y_int.bit_length() + 7) // 8 or 1
    
    data += PREFIX_EXTENSION
    data += x_len.to_bytes(1, 'big')
    data += x_int.to_bytes(x_len, 'big')
    data += y_len.to_bytes(1, 'big')
    data += y_int.to_bytes(y_len, 'big')
    
    # Store the stem length and stem
    data += len(stem).to_bytes(1, 'big')
    data += stem
    
    # Store the single child reference (always 32 bytes)
    data += child_hash
    
    return zlib.compress(data, level=3)

# def deserialize_extension_node(data, idx):
#     # ... extract x and y using your standard logic ...
#     commitment = (b.FQ(x), b.FQ(y))
    
#     stem_len = data[idx]
#     idx += 1
#     stem = data[idx:idx+stem_len]
#     idx += stem_len
    
#     child_hash = data[idx:idx+32]
    
#     return commitment, stem, child_hash


def deserialize_extension_node(data, idx):
    """
    Deserializes an EIP-6800 Extension Node payload.
    """
    # 1. Extract x length and value
    x_len = data[idx]
    idx += 1
    x = int.from_bytes(data[idx:idx+x_len], 'big')
    idx += x_len
    
    # 2. Extract y length and value
    y_len = data[idx]
    idx += 1
    y = int.from_bytes(data[idx:idx+y_len], 'big')
    idx += y_len
    
    # 3. Reconstruct commitment
    commitment = (b.FQ(x), b.FQ(y))
    
    # 4. Extract stem length and stem bytes
    stem_len = data[idx]
    idx += 1
    stem = data[idx:idx+stem_len]
    idx += stem_len
    
    # 5. Extract the single child hash reference (always 32 bytes)
    child_hash = data[idx:idx+32]
    
    return commitment, stem, child_hash


def deserialize_array_node(data, idx):
    """
    Helper method utilizing your previous bitmap logic to deserialize 
    256-wide arrays (used by both Internal and Suffix nodes).
    """
    # 1. Extract x and y
    x_len = data[idx]
    idx += 1
    x = int.from_bytes(data[idx:idx+x_len], 'big')
    idx += x_len
    
    y_len = data[idx]
    idx += 1
    y = int.from_bytes(data[idx:idx+y_len], 'big')
    idx += y_len
    
    commitment = (b.FQ(x), b.FQ(y))

    # 2. Extract bitmap length
    bf = int.from_bytes(data[idx:idx+2], 'big')
    idx += 2

    bitmap_bytes = (bf + 7) // 8
    bitmap = data[idx:idx+bitmap_bytes]
    idx += bitmap_bytes

    # 3. Reconstruct the 256-wide array based on the bitmap
    child_hashes = []
    for i in range(bf):
        byte_idx = i // 8
        bit_idx = i % 8
        if (bitmap[byte_idx] >> bit_idx) & 1:
            child_hashes.append(data[idx:idx+32])
            idx += 32
        else:
            child_hashes.append(None)

    return commitment, child_hashes


def deserialize_any_node(serialized):
    """
    Master router that reads the 1-byte prefix and dispatches the payload
    to the correct deserializer.
    """
    data = zlib.decompress(serialized)
    
    # Peek at the 1-byte type flag
    prefix = data[0:1]
    
    if prefix == PREFIX_INTERNAL or prefix == PREFIX_SUFFIX:
        # Pass idx=1 to skip the prefix byte
        commitment, child_hashes = deserialize_array_node(data, 1)
        return prefix, commitment, child_hashes
        
    elif prefix == PREFIX_EXTENSION:
        # Pass idx=1 to skip the prefix byte
        commitment, stem, child_hash = deserialize_extension_node(data, 1)
        return prefix, commitment, stem, child_hash
        
    else:
        raise ValueError(f"Unknown node prefix encountered: {prefix}")
