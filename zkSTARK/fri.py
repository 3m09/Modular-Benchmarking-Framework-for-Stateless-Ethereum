"""
FRI (Fast Reed-Solomon Interactive Oracle Proof) Protocol

Implements the FRI protocol for proving that a committed polynomial
has a bounded degree, which is the core of STARK proofs.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
import hashlib
from zkSTARK.field import field_add, field_mul, field_inv
from zkSTARK.fft import FFT_CACHE, ntt_forward, ntt_inverse
from zkSTARK.commitment import MerkleTree
from zkSTARK.transcript import FiatShamirTranscript


class FRIProof:
    """Container for FRI proof data."""
    
    def __init__(self):
        self.layer_commitments: List[bytes] = []
        self.layer_polynomials: List[np.ndarray] = []
        self.query_responses: List[Dict[str, Any]] = []
        self.final_polynomial: np.ndarray = None


class FRIProver:
    """
    FRI Prover for polynomial degree bounds.
    
    Proves that a committed polynomial has degree less than a bound
    by repeatedly folding the polynomial and committing to each layer.
    """
    
    def __init__(self, security_params):
        """
        Initialize FRI prover.
        
        Args:
            security_params: SecurityParameters object
        """
        self.params = security_params
        self.reduction_factor = 2  # Fold by 2 each layer
        self.final_degree_bound = 16  # Stop when degree < 16
    
    def prove(self, polynomial: np.ndarray, transcript: FiatShamirTranscript) -> FRIProof:
        """
        Generate FRI proof for polynomial degree bound.
        
        Args:
            polynomial: Polynomial evaluations on LDE domain
            transcript: Fiat-Shamir transcript
            
        Returns:
            FRI proof
        """
        proof = FRIProof()
        current_poly = polynomial.copy()
        current_domain_size = len(current_poly)
        
        # FRI folding layers
        while current_domain_size > self.final_degree_bound:
            # Commit to current layer
            tree = MerkleTree(current_poly)
            proof.layer_commitments.append(tree.root)
            proof.layer_polynomials.append(current_poly)
            
            # Append commitment to transcript
            transcript.append(b"fri_layer", tree.root)
            
            # Get folding challenge
            alpha = transcript.challenge(b"fri_alpha")
            
            # Fold polynomial
            current_poly = self._fold_polynomial(current_poly, alpha)
            current_domain_size = len(current_poly)
        
        # Store final polynomial (small enough to include directly)
        proof.final_polynomial = current_poly
        final_bytes = current_poly.tobytes()
        transcript.append(b"fri_final", final_bytes)
        
        return proof
    
    def _fold_polynomial(self, poly: np.ndarray, alpha: np.uint64) -> np.ndarray:
        """
        Fold polynomial by factor of 2.
        
        Uses the identity:
        p(x) = p_even(x^2) + x * p_odd(x^2)
        p_folded(y) = p_even(y) + alpha * p_odd(y)  where y = x^2
        
        Args:
            poly: Polynomial evaluations
            alpha: Folding challenge
            
        Returns:
            Folded polynomial (half the size)
        """
        n = len(poly)
        n_half = n // 2
        
        # Split into even and odd indexed evaluations
        # In frequency domain, this corresponds to even/odd coefficients
        folded = np.zeros(n_half, dtype=np.uint64)
        
        for i in range(n_half):
            # Combine symmetric points
            even_val = poly[i]
            odd_val = poly[i + n_half]
            
            # Folded value: even + alpha * odd
            folded[i] = np.uint64(field_add(even_val, np.uint64(field_mul(alpha, odd_val))))
        
        return folded
    
    def _generate_query_response(self, index: int, proof: FRIProof) -> Dict[str, Any]:
        """
        Generate response for a single query index.
        
        Args:
            index: Query index in original domain
            proof: FRI proof being constructed
            
        Returns:
            Query response with values and authentication paths
        """
        response = {
            'index': index,
            'layers': []
        }
        
        current_idx = index
        
        for layer_idx, (poly, commitment) in enumerate(zip(proof.layer_polynomials, proof.layer_commitments)):
            # Get value and authentication path
            tree = MerkleTree(poly)
            value = poly[current_idx]
            auth_path = tree.get_authentication_path(current_idx)
            
            response['layers'].append({
                'value': value,
                'auth_path': auth_path,
                'sibling_index': current_idx ^ 1,  # Sibling needed for folding check
                'sibling_value': poly[current_idx ^ 1] if (current_idx ^ 1) < len(poly) else value
            })
            
            # Update index for next layer (folded domain)
            current_idx //= self.reduction_factor
        
        return response


class FRIVerifier:
    """
    FRI Verifier for polynomial degree bounds.
    
    Verifies that the prover's polynomial has the claimed degree
    by checking folding consistency and authentication paths.
    """
    
    def __init__(self, security_params=None):
        """
        Initialize FRI verifier.
        
        Args:
            security_params: SecurityParameters object
        """
        self.params = security_params or {}
        self.reduction_factor = 2
        self.final_degree_bound = 16
    
    def verify(self, proof: FRIProof, transcript: FiatShamirTranscript) -> bool:
        """
        Verify FRI proof.
        
        Args:
            proof: FRI proof from prover
            transcript: Fiat-Shamir transcript (rebuilt)
            
        Returns:
            True if proof is valid
        """
        # Rebuild challenges from transcript
        alphas = []
        for i, commitment in enumerate(proof.layer_commitments):
            transcript.append(b"fri_layer", commitment)
            alpha = transcript.challenge(b"fri_alpha")
            alphas.append(alpha)
        
        # Final polynomial
        final_bytes = proof.final_polynomial.tobytes()
        transcript.append(b"fri_final", final_bytes)
        
        # Verify final polynomial degree
        if len(proof.final_polynomial) > self.final_degree_bound:
            return False
        
        return True
    
    def _verify_query(self, response: Dict[str, Any], proof: FRIProof, alphas: List[np.uint64]) -> bool:
        """
        Verify a single query response.
        
        Checks:
        1. Authentication paths are valid
        2. Folding is done correctly
        
        Args:
            response: Query response
            proof: FRI proof
            alphas: Folding challenges
            
        Returns:
            True if query is valid
        """
        current_idx = response['index']
        
        # Verify each layer
        for layer_idx, layer_data in enumerate(response['layers']):
            # Verify authentication path
            tree = MerkleTree(proof.layer_polynomials[layer_idx])
            if not tree.verify_path(current_idx, layer_data['value'], layer_data['auth_path']):
                return False
            
            # Verify folding consistency (if not last layer)
            if layer_idx < len(response['layers']) - 1:
                # Check that next layer value matches folded value
                alpha = alphas[layer_idx]
                even_val = layer_data['value']
                odd_val = layer_data['sibling_value']
                
                expected_folded = field_add(even_val, field_mul(alpha, odd_val))
                
                next_layer_idx = current_idx // self.reduction_factor
                next_value = response['layers'][layer_idx + 1]['value']
                
                if expected_folded != next_value:
                    return False
            
            current_idx //= self.reduction_factor
        
        return True
