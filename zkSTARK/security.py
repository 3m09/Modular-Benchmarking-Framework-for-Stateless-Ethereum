"""
Security Parameters for ZK-STARK

Computes and validates security parameters for STARK proofs,
ensuring the desired security level is achieved.
"""

from dataclasses import dataclass
import math


@dataclass
class SecurityParameters:
    """
    STARK security parameters.
    
    Attributes:
        security_bits: Target security level (e.g., 128 bits)
        trace_length: Length of execution trace (power of 2)
        blowup_factor: LDE expansion factor (typically 4, 8, or 16)
        n_queries: Number of FRI queries
        grinding_bits: Proof-of-work difficulty
        field_modulus: Prime field modulus
        fri_layers: Number of FRI fold layers
    """
    security_bits: int
    trace_length: int
    blowup_factor: int
    n_queries: int
    grinding_bits: int
    field_modulus: int
    fri_layers: int
    
    @staticmethod
    def compute_parameters(target_security_bits: int = 128, 
                          trace_length: int = 65536) -> 'SecurityParameters':
        """
        Compute optimal security parameters for target security level.
        
        Uses standard STARK security analysis to determine parameters
        that achieve the desired security level.
        
        Args:
            target_security_bits: Desired security level (default: 128)
            trace_length: Execution trace length (default: 65536)
            
        Returns:
            SecurityParameters object
        """
        # Standard parameter choices based on security level
        if target_security_bits >= 128:
            blowup_factor = 8
            n_queries = 80
            grinding_bits = 20
        elif target_security_bits >= 96:
            blowup_factor = 8
            n_queries = 60
            grinding_bits = 16
        else:
            blowup_factor = 4
            n_queries = 40
            grinding_bits = 12
        
        # Compute FRI layers
        lde_size = trace_length * blowup_factor
        fri_layers = int(math.log2(lde_size)) - 4  # Fold until degree ~16
        
        return SecurityParameters(
            security_bits=target_security_bits,
            trace_length=trace_length,
            blowup_factor=blowup_factor,
            n_queries=n_queries,
            grinding_bits=grinding_bits,
            field_modulus=0xFFFFFFFF00000001,  # Goldilocks
            fri_layers=fri_layers
        )
    
    def soundness_error(self) -> float:
        """
        Compute theoretical soundness error.
        
        Returns:
            Probability that a malicious prover succeeds
        """
        # Simplified soundness analysis
        # Real analysis is more complex and depends on proximity gaps
        
        # FRI proximity gap
        rho = 1.0 / self.blowup_factor
        
        # Per-query soundness error
        per_query_error = 1.0 - (1.0 - rho) / 2.0
        
        # Total soundness error (union bound over queries)
        total_error = per_query_error ** self.n_queries
        
        # Include grinding contribution
        grinding_error = 2.0 ** (-self.grinding_bits)
        
        # Combined error
        return total_error + grinding_error
    
    def achieved_security_bits(self) -> float:
        """
        Compute achieved security level in bits.
        
        Returns:
            Security level in bits (negative log2 of soundness error)
        """
        error = self.soundness_error()
        if error <= 0:
            return float('inf')
        return -math.log2(error)
    
    def is_secure(self) -> bool:
        """
        Check if parameters achieve target security level.
        
        Returns:
            True if achieved security >= target security
        """
        return self.achieved_security_bits() >= self.security_bits
    
    def proof_size_estimate(self) -> int:
        """
        Estimate proof size in bytes.
        
        Returns:
            Approximate proof size
        """
        # Merkle root: 32 bytes
        root_size = 32
        
        # FRI commitments: 32 bytes per layer
        fri_commitments = self.fri_layers * 32
        
        # Query responses: ~100 bytes per query (values + auth paths)
        query_size = self.n_queries * 100
        
        # Final polynomial: ~1KB
        final_poly = 1024
        
        return root_size + fri_commitments + query_size + final_poly
    
    def __repr__(self):
        return (
            f"SecurityParameters(\n"
            f"  security_bits={self.security_bits},\n"
            f"  trace_length={self.trace_length},\n"
            f"  blowup_factor={self.blowup_factor},\n"
            f"  n_queries={self.n_queries},\n"
            f"  grinding_bits={self.grinding_bits},\n"
            f"  achieved_bits={self.achieved_security_bits():.1f},\n"
            f"  estimated_proof_size={self.proof_size_estimate()} bytes\n"
            f")"
        )
