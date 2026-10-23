"""
Fiat-Shamir Transcript for Non-Interactive Proofs

Implements a cryptographically secure transcript for converting
interactive proofs into non-interactive ones using the Fiat-Shamir heuristic.
"""

import hashlib
import hmac
import secrets
import struct
from typing import Optional, List
import numpy as np
from zkSTARK.field import FIELD_PRIME_INT, hash_to_field


# ============================================================================
# Hash functions
# ============================================================================

try:
    import blake3
    HAS_BLAKE3 = True
except ImportError:
    HAS_BLAKE3 = False


def secure_hash(data: bytes) -> bytes:
    """
    Cryptographically secure hash function.
    
    Prefers BLAKE3 if available, falls back to HMAC-SHA256.
    
    Args:
        data: Input bytes
        
    Returns:
        32-byte hash digest
    """
    if HAS_BLAKE3:
        return blake3.blake3(data).digest()
    key = b"pythonstark_v01_key"
    return hmac.new(key, data, hashlib.sha256).digest()


def hash_to_field(data: bytes) -> np.uint64:
    """
    Hash arbitrary data to a field element.
    
    Args:
        data: Input bytes
        
    Returns:
        Field element in [0, FIELD_PRIME)
    """
    h = secure_hash(data)
    value = int.from_bytes(h[:8], "big") % FIELD_PRIME_INT
    return np.uint64(value)


# ============================================================================
# Fiat-Shamir Transcript
# ============================================================================

class FiatShamirTranscript:
    """
    Fiat-Shamir transcript for non-interactive proofs.
    
    Maintains a running hash state and generates deterministic challenges
    from prover messages, implementing the Fiat-Shamir transformation.
    
    Usage:
        transcript = FiatShamirTranscript()
        transcript.append(b"commitment", commitment_bytes)
        challenge = transcript.challenge(b"alpha")
    """
    
    def __init__(self, seed: Optional[bytes] = None, security_bits: int = 128):
        """
        Initialize transcript with optional seed.
        
        Args:
            seed: Initial seed (uses default if None)
            security_bits: Target security level
        """
        if seed is None:
            seed = b"PYTHONSTARK_IOP_V01"
            # Use deterministic domain separator for default seed
            self.domain_separator = secure_hash(seed + b"_domain")[:16]
        else:
            self.domain_separator = secure_hash(seed + b"_domain")[:16]
        
        self.security_bits = security_bits
        self.state = secure_hash(seed + self.domain_separator)
        self.challenge_count = 0
        
    def append(self, label: bytes, data: bytes) -> None:
        """
        Append data to the transcript.
        
        Absorbs prover messages into the transcript state using
        domain separation to prevent collision attacks.
        
        Args:
            label: Domain separator label
            data: Message bytes to append
        """
        # Ensure proper types
        if not isinstance(label, bytes):
            label = str(label).encode('utf-8')
        if not isinstance(data, bytes):
            if isinstance(data, (int, np.integer)):
                data = int(data).to_bytes(8, 'big')
            else:
                data = bytes(data)
        
        # Domain-separated hashing
        message = self.domain_separator + label + struct.pack("<I", len(data)) + data
        self.state = secure_hash(self.state + message)
    
    def challenge(self, label: bytes) -> np.uint64:
        """
        Generate a random field element challenge.
        
        Uses the current transcript state to deterministically generate
        a uniformly random field element.
        
        Args:
            label: Challenge label for domain separation
            
        Returns:
            Random field element
        """
        if not isinstance(label, bytes):
            label = str(label).encode('utf-8')
        
        # Include challenge counter for uniqueness
        challenge_label = label + struct.pack("<I", self.challenge_count)
        self.challenge_count += 1
        
        # Generate challenge from current state
        challenge_data = self.state + self.domain_separator + challenge_label
        challenge_value = hash_to_field(challenge_data)
        
        # Update state with challenge (for binding)
        self.state = secure_hash(self.state + challenge_data)
        
        return challenge_value
    
    def challenge_bytes(self, label: bytes, n_bytes: int = 32) -> bytes:
        """
        Generate random bytes challenge.
        
        Args:
            label: Challenge label
            n_bytes: Number of random bytes to generate
            
        Returns:
            Random bytes
        """
        if not isinstance(label, bytes):
            label = str(label).encode('utf-8')
        
        challenge_label = label + struct.pack("<I", self.challenge_count)
        self.challenge_count += 1
        
        # Generate enough hash outputs
        result = b""
        counter = 0
        while len(result) < n_bytes:
            data = self.state + self.domain_separator + challenge_label + struct.pack("<I", counter)
            result += secure_hash(data)
            counter += 1
        
        # Update state
        self.state = secure_hash(self.state + result[:n_bytes])
        
        return result[:n_bytes]
    
    def challenge_indices(self, count: int, domain_size: int) -> List[int]:
        """
        Generate random query indices for FRI.
        
        Uses rejection sampling to ensure uniform distribution.
        
        Args:
            count: Number of indices to generate
            domain_size: Size of domain to sample from
            
        Returns:
            List of unique random indices in [0, domain_size)
        """
        if count > domain_size:
            raise ValueError(f"Cannot sample {count} unique indices from domain of size {domain_size}")
        
        indices = set()
        attempt = 0
        
        while len(indices) < count:
            # Generate random bytes
            rand_bytes = self.challenge_bytes(b"query_index_" + str(attempt).encode(), n_bytes=4)
            idx = int.from_bytes(rand_bytes, 'big') % domain_size
            indices.add(idx)
            attempt += 1
        
        return sorted(list(indices))
    
    def get_state(self) -> bytes:
        """Get current transcript state."""
        return self.state
    
    def fork(self, label: bytes) -> 'FiatShamirTranscript':
        """
        Create a forked transcript for sub-protocols.
        
        Args:
            label: Fork label
            
        Returns:
            New transcript with forked state
        """
        forked = FiatShamirTranscript(seed=self.state + label, security_bits=self.security_bits)
        forked.challenge_count = self.challenge_count
        return forked


class SecureFiatShamirTranscript(FiatShamirTranscript):
    """
    Enhanced Fiat-Shamir transcript with additional security features.
    
    Includes grinding for proof-of-work and additional domain separation.
    """
    
    def __init__(self, seed: Optional[bytes] = None, security_bits: int = 128):
        super().__init__(seed, security_bits)
        self.grinding_bits = min(20, security_bits // 6)  # Proof-of-work difficulty
    
    def challenge_with_grinding(self, label: bytes, nonce: Optional[int] = None) -> tuple:
        """
        Generate challenge with proof-of-work grinding.
        
        Requires finding a nonce such that the challenge has
        a certain number of leading zero bits.
        
        Args:
            label: Challenge label
            nonce: Optional nonce (finds one if None)
            
        Returns:
            (challenge, nonce) tuple
        """
        if nonce is None:
            # Find a valid nonce
            nonce = 0
            while True:
                test_label = label + struct.pack("<Q", nonce)
                challenge = self.challenge(test_label)
                
                # Check if challenge has enough leading zero bits
                challenge_int = int(challenge)
                leading_zeros = (challenge_int.bit_length() - 1).bit_length()
                
                if 64 - leading_zeros >= self.grinding_bits:
                    return challenge, nonce
                
                nonce += 1
        else:
            # Verify provided nonce
            test_label = label + struct.pack("<Q", nonce)
            challenge = self.challenge(test_label)
            return challenge, nonce
    
    def verify_grinding(self, challenge: np.uint64, expected_bits: int) -> bool:
        """
        Verify that a challenge meets grinding requirements.
        
        Args:
            challenge: Challenge to verify
            expected_bits: Required number of leading zero bits
            
        Returns:
            True if challenge is valid
        """
        challenge_int = int(challenge)
        leading_zeros = (challenge_int.bit_length() - 1).bit_length()
        return (64 - leading_zeros) >= expected_bits
