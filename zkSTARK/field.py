"""
Field Arithmetic Module for ZK-STARK

Implements arithmetic operations in the Goldilocks field (2^64 - 2^32 + 1).
This field is optimized for 64-bit architectures and STARK protocols.
"""

import numpy as np
from numba import njit, vectorize
import hashlib


# ============================================================================
# Field Configuration (Goldilocks: 2^64 - 2^32 + 1)
# ============================================================================

FIELD_PRIME = np.uint64(0xFFFFFFFF00000001)
FIELD_PRIME_INT = int(0xFFFFFFFF00000001)
EPSILON = np.uint64(0xFFFFFFFF)  # 2^32 - 1
GENERATOR = np.uint64(7)


# ============================================================================
# Field Arithmetic Operations
# ============================================================================

@vectorize(["uint64(uint64, uint64)"], nopython=True, cache=True)
def field_add(a, b):
    """Addition in Goldilocks field"""
    c = a + b
    return c - FIELD_PRIME if c >= FIELD_PRIME else c


@vectorize(["uint64(uint64, uint64)"], nopython=True, cache=True)
def field_sub(a, b):
    """Subtraction in Goldilocks field"""
    return a - b if a >= b else a + FIELD_PRIME - b


@njit(fastmath=True, cache=True, inline="always")
def field_mul(a, b):
    """Multiplication in Goldilocks field"""
    a_int = int(a)
    b_int = int(b)
    product = a_int * b_int
    
    # Fast reduction for Goldilocks
    hi = product >> 64
    lo = product & 0xFFFFFFFFFFFFFFFF
    
    reduced = lo + hi * int(EPSILON)
    
    if reduced >= FIELD_PRIME_INT:
        reduced -= FIELD_PRIME_INT
    
    return np.uint64(reduced)


@njit(fastmath=True, cache=True, inline="always")
def field_neg(a):
    """Negation in Goldilocks field"""
    return np.uint64(0) if a == 0 else FIELD_PRIME - a


@njit(fastmath=True, cache=True, inline="always")
def field_inv(a):
    """Multiplicative inverse using Fermat's little theorem: a^(p-2) mod p"""
    if a == 0:
        raise ValueError("Cannot invert zero")
    
    result = np.uint64(1)
    base = a
    exp = FIELD_PRIME_INT - 2
    
    while exp > 0:
        if exp & 1:
            result = field_mul(result, base)
        base = field_mul(base, base)
        exp >>= 1
    
    return result


@njit(fastmath=True, cache=True)
def field_div(a, b):
    """Division in Goldilocks field: a / b = a * b^(-1)"""
    return field_mul(a, field_inv(b))


@njit(fastmath=True, cache=True)
def field_pow(base, exp):
    """Exponentiation in Goldilocks field"""
    result = np.uint64(1)
    base_val = base
    exp_val = int(exp)
    
    while exp_val > 0:
        if exp_val & 1:
            result = field_mul(result, base_val)
        base_val = field_mul(base_val, base_val)
        exp_val >>= 1
    
    return result


# ============================================================================
# Hash to Field Conversion
# ============================================================================

def hash_to_field(data: bytes) -> np.uint64:
    """
    Hash arbitrary bytes to a Goldilocks field element.
    
    Args:
        data: Input bytes to hash
        
    Returns:
        Field element in [0, FIELD_PRIME)
    """
    # Use SHA-256 for hashing
    hash_digest = hashlib.sha256(data).digest()
    
    # Take first 8 bytes and convert to uint64
    value = int.from_bytes(hash_digest[:8], byteorder='big')
    
    # Reduce modulo field prime
    return np.uint64(value % FIELD_PRIME_INT)


def bytes_to_field_elements(data: bytes, chunk_size: int = 8) -> list:
    """
    Convert bytes to multiple field elements.
    
    Args:
        data: Input bytes
        chunk_size: Bytes per field element (default 8 for uint64)
        
    Returns:
        List of field elements
    """
    elements = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        # Pad if necessary
        if len(chunk) < chunk_size:
            chunk = chunk + b'\x00' * (chunk_size - len(chunk))
        value = int.from_bytes(chunk, byteorder='big')
        elements.append(np.uint64(value % FIELD_PRIME_INT))
    return elements


def field_element_to_bytes(element: np.uint64, length: int = 8) -> bytes:
    """
    Convert field element to bytes.
    
    Args:
        element: Field element
        length: Output byte length
        
    Returns:
        Bytes representation
    """
    return int(element).to_bytes(length, byteorder='big')


# ============================================================================
# Batch Operations
# ============================================================================

@njit(fastmath=True, cache=True, parallel=True)
def batch_field_add(a_array, b_array):
    """Vectorized field addition"""
    result = np.empty_like(a_array)
    for i in range(len(a_array)):
        result[i] = field_add(a_array[i], b_array[i])
    return result


@njit(fastmath=True, cache=True, parallel=True)
def batch_field_mul(a_array, b_array):
    """Vectorized field multiplication"""
    result = np.empty_like(a_array)
    for i in range(len(a_array)):
        result[i] = field_mul(a_array[i], b_array[i])
    return result


# ============================================================================
# Field Element Class (Optional OOP Interface)
# ============================================================================

class FieldElement:
    """
    Object-oriented wrapper for field elements.
    Useful for cleaner code but slower than direct numba functions.
    """
    
    def __init__(self, value):
        if isinstance(value, FieldElement):
            self.value = value.value
        elif isinstance(value, (int, np.integer)):
            self.value = np.uint64(int(value) % FIELD_PRIME_INT)
        elif isinstance(value, bytes):
            self.value = hash_to_field(value)
        else:
            self.value = np.uint64(value)
    
    def __add__(self, other):
        other_val = other.value if isinstance(other, FieldElement) else np.uint64(other)
        return FieldElement(field_add(self.value, other_val))
    
    def __sub__(self, other):
        other_val = other.value if isinstance(other, FieldElement) else np.uint64(other)
        return FieldElement(field_sub(self.value, other_val))
    
    def __mul__(self, other):
        other_val = other.value if isinstance(other, FieldElement) else np.uint64(other)
        return FieldElement(field_mul(self.value, other_val))
    
    def __truediv__(self, other):
        other_val = other.value if isinstance(other, FieldElement) else np.uint64(other)
        return FieldElement(field_div(self.value, other_val))
    
    def __pow__(self, exp):
        return FieldElement(field_pow(self.value, int(exp)))
    
    def __neg__(self):
        return FieldElement(field_neg(self.value))
    
    def inverse(self):
        return FieldElement(field_inv(self.value))
    
    def __eq__(self, other):
        other_val = other.value if isinstance(other, FieldElement) else np.uint64(other)
        return self.value == other_val
    
    def __int__(self):
        return int(self.value)
    
    def __repr__(self):
        return f"FieldElement({int(self.value)})"
    
    def to_bytes(self, length=8):
        return field_element_to_bytes(self.value, length)


# ============================================================================
# Utility Functions
# ============================================================================

def is_field_element(value) -> bool:
    """Check if value is a valid field element"""
    if isinstance(value, (int, np.integer)):
        return 0 <= int(value) < FIELD_PRIME_INT
    return False


def random_field_element() -> np.uint64:
    """Generate random field element"""
    import secrets
    random_bytes = secrets.token_bytes(32)
    return hash_to_field(random_bytes)


# ============================================================================
# Module Exports
# ============================================================================

__all__ = [
    'FIELD_PRIME',
    'FIELD_PRIME_INT',
    'GENERATOR',
    'field_add',
    'field_sub',
    'field_mul',
    'field_div',
    'field_neg',
    'field_inv',
    'field_pow',
    'hash_to_field',
    'bytes_to_field_elements',
    'field_element_to_bytes',
    'batch_field_add',
    'batch_field_mul',
    'FieldElement',
    'is_field_element',
    'random_field_element'
]
