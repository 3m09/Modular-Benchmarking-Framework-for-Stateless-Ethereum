"""
Fast Fourier Transform (NTT) for ZK-STARK

Implements Number Theoretic Transform over the Goldilocks field
for efficient polynomial operations in STARK proving.
"""

import numpy as np
from numba import njit
from zkSTARK.field import (
    FIELD_PRIME, FIELD_PRIME_INT, GENERATOR,
    field_add, field_sub, field_mul, field_inv, field_pow
)


# ============================================================================
# FFT Cache for twiddle factors
# ============================================================================

class FFTCache:
    """Cache for FFT twiddle factors and roots of unity."""

    def __init__(self):
        self.twiddle_cache = {}
        self.omega_cache = {}

    def get_omega(self, n: int) -> np.uint64:
        """
        Get the n-th root of unity.
        
        Args:
            n: Order of root (must divide FIELD_PRIME - 1)
            
        Returns:
            omega such that omega^n = 1
        """
        if n not in self.omega_cache:
            exponent = (FIELD_PRIME_INT - 1) // n
            generator_int = int(GENERATOR)
            value = pow(generator_int, exponent, FIELD_PRIME_INT)
            self.omega_cache[n] = np.uint64(value)
        return self.omega_cache[n]

    def get_twiddles(self, n: int) -> np.ndarray:
        """
        Get twiddle factors for FFT of size n.
        
        Twiddles are powers of omega: [1, omega, omega^2, ..., omega^(n-1)]
        
        Args:
            n: FFT size
            
        Returns:
            Array of twiddle factors
        """
        if n not in self.twiddle_cache:
            omega = self.get_omega(n)
            twiddles = np.zeros(n, dtype=np.uint64)
            twiddles[0] = np.uint64(1)
            current_int = 1
            omega_int = int(omega)
            for i in range(1, n):
                current_int = (current_int * omega_int) % FIELD_PRIME_INT
                twiddles[i] = np.uint64(current_int)
            self.twiddle_cache[n] = twiddles
        return self.twiddle_cache[n]


# Global FFT cache
FFT_CACHE = FFTCache()


# ============================================================================
# NTT Implementation
# ============================================================================

@njit(fastmath=True, cache=True)
def _bit_length_minus_one(n: int) -> int:
    """Compute floor(log2(n))."""
    bits = 0
    temp = n
    while temp > 1:
        temp >>= 1
        bits += 1
    return bits - 1


@njit(fastmath=True, cache=True)
def ntt_forward(values: np.ndarray, twiddles: np.ndarray) -> np.ndarray:
    """
    Forward Number Theoretic Transform (Cooley-Tukey algorithm).
    
    Computes the DFT of values in the field:
    Y[k] = sum(values[j] * omega^(j*k) for j in range(n))
    
    Args:
        values: Input polynomial coefficients
        twiddles: Twiddle factors (powers of omega)
        
    Returns:
        Transformed values (polynomial evaluations)
    """
    n = len(values)
    result = values.copy()

    bits = _bit_length_minus_one(n)

    # Bit-reversal permutation
    for i in range(n):
        j = 0
        temp_i = i
        for b in range(bits):
            if temp_i & (1 << b):
                j |= 1 << (bits - 1 - b)
        if i < j:
            tmp = result[i]
            result[i] = result[j]
            result[j] = tmp

    # Butterfly operations
    length = 2
    while length <= n:
        half_length = length >> 1
        step = n // length
        for start in range(0, n, length):
            twiddle_idx = 0
            for k in range(half_length):
                idx1 = start + k
                idx2 = start + k + half_length
                w = twiddles[twiddle_idx]
                twiddle_idx += step
                t = field_mul(w, result[idx2])
                a_val = result[idx1]
                result[idx2] = field_sub(a_val, t)
                result[idx1] = field_add(a_val, t)
        length <<= 1

    return result


@njit(fastmath=True, cache=True)
def ntt_inverse(values: np.ndarray, twiddles: np.ndarray) -> np.ndarray:
    """
    Inverse Number Theoretic Transform.
    
    Recovers polynomial coefficients from evaluations.
    
    Args:
        values: Polynomial evaluations
        twiddles: Twiddle factors
        
    Returns:
        Polynomial coefficients
    """
    n = len(values)
    
    # Invert twiddle factors
    inv_twiddles = np.zeros(n, dtype=np.uint64)
    for i in range(n):
        inv_twiddles[i] = field_inv(twiddles[i])

    # Forward NTT with inverted twiddles
    result = ntt_forward(values, inv_twiddles)

    # Scale by 1/n
    n_inv = field_inv(np.uint64(n))
    for i in range(len(result)):
        result[i] = field_mul(result[i], n_inv)

    return result


# ============================================================================
# Low-Degree Extension (LDE)
# ============================================================================

def compute_lde(trace_column: np.ndarray, blowup_factor: int) -> np.ndarray:
    """
    Compute Low-Degree Extension of a trace column.
    
    This is a core operation in STARK proving:
    1. Interpolate polynomial from trace values (INTT)
    2. Extend to larger domain (zero-padding coefficients)
    3. Evaluate on extended domain (NTT)
    
    Args:
        trace_column: Trace values at original domain
        blowup_factor: Extension factor (e.g., 8 for 8x larger domain)
        
    Returns:
        Polynomial evaluated on extended domain
    """
    n = len(trace_column)

    # Ensure trace length is power of 2
    if n & (n - 1) != 0:
        next_pow2 = 1
        while next_pow2 < n:
            next_pow2 <<= 1
        padded = np.zeros(next_pow2, dtype=np.uint64)
        padded[:n] = trace_column.astype(np.uint64)
        trace_column = padded
        n = next_pow2
    else:
        trace_column = trace_column.astype(np.uint64)

    # Step 1: Interpolate (INTT to get coefficients)
    twiddles = FFT_CACHE.get_twiddles(n)
    coeffs = ntt_inverse(trace_column, twiddles)

    # Step 2: Extend domain by zero-padding
    extended_size = n * blowup_factor
    coeffs_extended = np.zeros(extended_size, dtype=np.uint64)
    coeffs_extended[:n] = coeffs

    # Step 3: Evaluate on extended domain (NTT)
    twiddles_extended = FFT_CACHE.get_twiddles(extended_size)
    lde_values = ntt_forward(coeffs_extended, twiddles_extended)

    return lde_values


# ============================================================================
# Polynomial operations
# ============================================================================

def polynomial_eval_at(coeffs: np.ndarray, point: np.uint64) -> np.uint64:
    """
    Evaluate polynomial at a point using Horner's method.
    
    Args:
        coeffs: Polynomial coefficients [c0, c1, c2, ...]
        point: Evaluation point
        
    Returns:
        p(point) where p(x) = c0 + c1*x + c2*x^2 + ...
    """
    if len(coeffs) == 0:
        return np.uint64(0)
    
    result = coeffs[-1]
    for i in range(len(coeffs) - 2, -1, -1):
        result = field_add(field_mul(result, point), coeffs[i])
    
    return result


def polynomial_multiply(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """
    Multiply two polynomials using FFT.
    
    Args:
        a, b: Polynomial coefficients
        
    Returns:
        Coefficients of a(x) * b(x)
    """
    n = len(a) + len(b) - 1
    
    # Find next power of 2
    fft_size = 1
    while fft_size < n:
        fft_size <<= 1
    
    # Zero-pad
    a_padded = np.zeros(fft_size, dtype=np.uint64)
    b_padded = np.zeros(fft_size, dtype=np.uint64)
    a_padded[:len(a)] = a
    b_padded[:len(b)] = b
    
    # Transform to evaluation domain
    twiddles = FFT_CACHE.get_twiddles(fft_size)
    a_eval = ntt_forward(a_padded, twiddles)
    b_eval = ntt_forward(b_padded, twiddles)
    
    # Point-wise multiplication
    c_eval = np.zeros(fft_size, dtype=np.uint64)
    for i in range(fft_size):
        c_eval[i] = field_mul(a_eval[i], b_eval[i])
    
    # Transform back to coefficient domain
    c_coeffs = ntt_inverse(c_eval, twiddles)
    
    return c_coeffs[:n]


def batch_polynomial_eval(coeffs_list, point: np.uint64):
    """
    Evaluate multiple polynomials at the same point.
    
    Args:
        coeffs_list: List of polynomial coefficient arrays
        point: Evaluation point
        
    Returns:
        List of evaluations
    """
    return [polynomial_eval_at(coeffs, point) for coeffs in coeffs_list]
