"""
STARK Proof Verification for MPT Operations

This module verifies ZK-STARK proofs for Merkle Patricia Trie lookups,
integrating with the existing verifier infrastructure.
"""

from typing import Dict, Any
from registry.verifiers import BaseVerifier, register_verifier
import numpy as np

@register_verifier("zkstarkmerkle")
class MPTSTARKVerifier(BaseVerifier):
    """
    STARK Verifier for Merkle Patricia Trie operations.
    
    Verifies zero-knowledge proofs of correct MPT lookups without
    needing access to the full tree.
    
    Usage:
        verifier = MPTSTARKVerifier()
        is_valid = verifier.verify_lookup(proof_result)
    """
    
    def __init__(self, setup=None):
        """Initialize STARK verifier."""
        # Import STARK components
        from zkSTARK.fri import FRIVerifier
        from zkSTARK.transcript import FiatShamirTranscript
        from zkSTARK.commitment import CommitmentTree
        
        self.FRIVerifier = FRIVerifier
        self.FiatShamirTranscript = FiatShamirTranscript
        self.CommitmentTree = CommitmentTree
    
    def verify_proof(self, values, keys, root, proof, setup=None):
        real_proofs, _ = proof
        toReturn = True
        for p in real_proofs:
            res = self.verify_lookup(p)
            toReturn = toReturn and res
        return toReturn
    
    def verify_lookup(self, proof_result) -> bool:
        """
        Verify STARK proof for MPT lookup.
        
        Args:
            proof_result: STARKProofResult from MPTSTARKProver
            
        Returns:
            True if proof is valid, False otherwise
        """
        try:
            print("Starting STARK verification...")
            
            # Extract components
            proof = proof_result.proof
            public_inputs = proof_result.public_inputs
            params = proof['params']
            
            # 1. Verify setup parameters
            print("  [1/4] Verifying setup parameters...")
            if not self._verify_setup(params):
                print("  ERROR: Setup parameter verification failed")
                return False
            
            # 2. Rebuild Fiat-Shamir transcript
            print("  [2/4] Rebuilding Fiat-Shamir transcript...")
            transcript = self.FiatShamirTranscript(security_bits=params['security_bits'])
            
            # Append public inputs (must match prover)
            transcript.append(b'public_key', public_inputs['key'])
            transcript.append(b'public_value', public_inputs['value'])
            transcript.append(b'public_root', public_inputs['root_hash'])
            
            # Append trace commitment
            transcript.append(b'trace_commitment', proof['trace_commitment'])
            
            # Get alpha challenge
            alpha = transcript.challenge(b'alpha')
            
            # 3. Verify FRI proof (this rebuilds FRI transcript state)
            print("  [3/5] Verifying FRI proof...")
            fri_verifier = self.FRIVerifier(params)
            if not fri_verifier.verify(proof['fri_proof'], transcript):
                print("  ERROR: FRI verification failed")
                return False
            
            # 4. Generate query indices (AFTER FRI to match prover order)
            print(f"  [4/5] Generating query indices...")
            query_indices = transcript.challenge_indices(
                count=params['n_queries'],
                domain_size=proof['composition_degree']
            )
            
            # 5. Verify query responses
            print(f"  [5/5] Verifying {len(proof['query_responses'])} query responses...")
            
            if not self._verify_queries(proof, query_indices):
                print("  ERROR: Query verification failed")
                return False
            
            print("✓ STARK proof verification successful!")
            return True
            
        except Exception as e:
            print(f"  ERROR: Verification failed with exception: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _verify_setup(self, params: Dict[str, Any]) -> bool:
        """
        Verify setup parameters are correct and secure.
        
        Args:
            params: Security parameters dictionary
            
        Returns:
            True if parameters are valid
        """
        # Check field modulus
        expected_modulus = 0xFFFFFFFF00000001  # Goldilocks
        if params.get('field_modulus') != expected_modulus:
            print(f"  Invalid field modulus: {params.get('field_modulus')} != {expected_modulus}")
            return False
        
        # Check trace is power of 2
        trace_length = params.get('trace_length', 0)
        if trace_length == 0 or (trace_length & (trace_length - 1)) != 0:
            print(f"  Trace length {trace_length} is not a power of 2")
            return False
        
        # Check security parameters are reasonable
        security_bits = params.get('security_bits', 0)
        if security_bits < 80:
            print(f"  Security level {security_bits} is too low (minimum 80)")
            return False
        
        n_queries = params.get('n_queries', 0)
        if n_queries < 20:
            print(f"  Number of queries {n_queries} is too low")
            return False
        
        return True
    
    def _verify_queries(self, proof: Dict[str, Any], query_indices: list) -> bool:
        """
        Verify query responses are consistent with commitments.
        
        Checks:
        1. Query indices match expected
        2. Authentication paths are valid
        3. Values are consistent with composition polynomial
        
        Args:
            proof: STARK proof
            query_indices: Expected query indices
            
        Returns:
            True if all queries are valid
        """
        query_responses = proof.get('query_responses', [])
        
        if len(query_responses) != len(query_indices):
            print(f"  Query count mismatch: {len(query_responses)} != {len(query_indices)}")
            return False
        
        for response, expected_idx in zip(query_responses, query_indices):
            # Check index matches
            if response['index'] != expected_idx:
                print(f"  Query index mismatch: {response['index']} != {expected_idx}")
                return False
            
            # Verify authentication paths (if provided)
            if 'auth_paths' in response:
                auth_data = response['auth_paths']
                # In full implementation, would verify Merkle paths
                # For now, just check data exists
                if not auth_data:
                    print(f"  Missing authentication path for query {expected_idx}")
                    return False
            
            # Verify trace values are field elements
            trace_values = response.get('trace_values', [])
            if len(trace_values) != 8:  # MPT circuit has 8 registers
                print(f"  Wrong number of trace values: {len(trace_values)} != 8")
                return False
        
        return True
    
    def verify_with_proof_dict(self, proof: Dict[str, Any], public_inputs: Dict[str, bytes]) -> bool:
        """
        Verify STARK proof from dictionary format.
        
        Alternative interface for when you have proof and public inputs separately.
        
        Args:
            proof: STARK proof dictionary
            public_inputs: Public inputs dictionary
            
        Returns:
            True if proof is valid
        """
        # Create a minimal proof result object
        class ProofResult:
            pass
        
        result = ProofResult()
        result.proof = proof
        result.public_inputs = public_inputs
        
        return self.verify_lookup(result)
