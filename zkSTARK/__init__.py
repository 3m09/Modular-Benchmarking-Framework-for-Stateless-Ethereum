"""
zkSTARK - Zero-Knowledge STARK Implementation

A modular ZK-STARK proof system for Merkle Patricia Trie operations.
Provides field arithmetic, FFT operations, FRI protocol, and circuit definitions.
"""

from zkSTARK.field import (
    FIELD_PRIME,
    field_add,
    field_mul,
    field_sub,
    field_inv,
    field_pow,
    FieldElement
)

from zkSTARK.security import SecurityParameters

__version__ = "0.1.0"
__all__ = [
    "FIELD_PRIME",
    "field_add",
    "field_mul",
    "field_sub",
    "field_inv",
    "field_pow",
    "FieldElement",
    "SecurityParameters",
]
