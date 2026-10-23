"""
STARK Proof Generation for MPT Operations

This module generates ZK-STARK proofs for Merkle Patricia Trie lookups,
integrating with the existing prover infrastructure.
"""

from typing import Dict, Any, List
import numpy as np
from tree.merkle_tree import MerklePatriciaTrie
from registry.provers import BaseProver, register_prover
from dataclasses import dataclass
import time


@dataclass
class STARKProofResult:
    """
    Complete STARK proof package for MPT operations.
    
    Attributes:
        proof: Core STARK proof components
        public_inputs: Public data (root_hash, key, value)
        metadata: Additional proof metadata
        proof_size_bytes: Total proof size
        proving_time_ms: Time taken to generate proof
    """
    proof: Dict[str, Any]
    public_inputs: Dict[str, bytes]
    metadata: Dict[str, Any]
    proof_size_bytes: int
    proving_time_ms: float

@register_prover("zkstarkmerkle")
class MPTSTARKProver(BaseProver):
    """
    STARK Prover for Merkle Patricia Trie operations.
    
    Generates zero-knowledge proofs that prove correct MPT lookups
    without revealing the entire tree structure.
    
    Usage:
        prover = MPTSTARKProver(security_bits=128)
        proof = prover.prove_lookup(proof_nodes, key, value)
    """
    
    def __init__(self, setup = None, security_bits: int = 128, trace_length: int = 65536):
        """
        Initialize STARK prover with security parameters.
        
        Args:
            security_bits: Target security level (default: 128)
            trace_length: Execution trace length, must be power of 2
        """
        self.security_bits = security_bits
        self.trace_length = trace_length
        
        # Import STARK components
        from zkSTARK.security import SecurityParameters
        from zkSTARK.field import FieldElement
        from zkSTARK.fri import FRIProver
        from zkSTARK.transcript import FiatShamirTranscript
        from zkSTARK.fft import compute_lde
        from zkSTARK.commitment import CommitmentTree
        
        # Compute security parameters
        self.params = SecurityParameters.compute_parameters(
            target_security_bits=security_bits,
            trace_length=trace_length
        )
        
        # Store references to modules
        self.FieldElement = FieldElement
        self.FRIProver = FRIProver
        self.FiatShamirTranscript = FiatShamirTranscript
        self.compute_lde = compute_lde
        self.CommitmentTree = CommitmentTree
    def generate_proof(self, tree: 'MerklePatriciaTrie', keys: List[bytes]) :
        """
        Generate Merkle proofs for multiple keys.
        
        Args:
            tree: MerklePatriciaTrie instance
            keys: List of keys to prove (bytes)
        """
        # Collect proof for each key
        commitments = []
        for key in keys:
            # get_proof_tree returns list of RLP-encoded nodes along the path
            proof_path = tree.get_proof_tree(key)
            value = tree.get(key)
            if proof_path is None:
                raise ValueError(f"Key not found in tree: {key.hex()}")
            proof = self.prove_lookup(proof_path, key, value)
            commitments.append(proof)
        
        # The "witness" in Merkle is the root hash
        # This is dummy witness to match interface
        witness = tree.root_hash()
        
        return commitments, witness
        
    
    def prove_lookup(self, proof_nodes: List[bytes], key: bytes, value: bytes) -> STARKProofResult:
        """
        Generate STARK proof for MPT lookup operation.
        
        Args:
            proof_nodes: List of RLP-encoded nodes from get_proof_tree()
            key: Lookup key (bytes)
            value: Expected value (bytes)
            
        Returns:
            STARKProofResult containing complete proof package
        """
        start_time = time.time()
        
        # 1. Create MPT circuit and generate trace
        from zkSTARK.circuits.mpt_circuit import MPTLookupCircuit, MPTConstraintSystem
        
        circuit = MPTLookupCircuit(proof_nodes, key, value)
        trace = circuit.generate_trace(n_steps=self.trace_length)
        
        # 2. Validate trace correctness
        if not self._validate_trace(trace):
            raise ValueError("Invalid execution trace generated")
        
        # 3. Generate STARK proof
        proof = self._generate_stark_proof(trace)
        
        # 4. Calculate metrics
        proving_time = (time.time() - start_time) * 1000  # Convert to ms
        proof_size = self._calculate_proof_size(proof)
        
        return STARKProofResult(
            proof=proof,
            public_inputs=trace.public_inputs,  # Use same dict from trace
            metadata={
                'proof_nodes_count': len(proof_nodes),
                'trace_length': self.trace_length,
                'security_bits': self.security_bits,
                'blowup_factor': self.params.blowup_factor,
                'n_queries': self.params.n_queries
            },
            proof_size_bytes=proof_size,
            proving_time_ms=proving_time
        )
    
    def _generate_stark_proof(self, trace) -> Dict[str, Any]:
        """
        Core STARK proof generation.
        
        Steps:
        1. Polynomial interpolation of trace columns (LDE)
        2. Commit to trace polynomials
        3. Compute composition polynomial (constraint checks)
        4. Generate FRI proof for composition polynomial
        5. Perform query phase
        
        Args:
            trace: ExecutionTrace object
            
        Returns:
            STARK proof dictionary
        """
        from zkSTARK.field import field_add, field_mul
        
        # Initialize Fiat-Shamir transcript
        transcript = self.FiatShamirTranscript(security_bits=self.security_bits)
        
        # Append public inputs to transcript
        transcript.append(b'public_key', trace.public_inputs['key'])
        transcript.append(b'public_value', trace.public_inputs['value'])
        transcript.append(b'public_root', trace.public_inputs['root_hash'])
        
        # Step 1: Low-degree extension of trace columns
        print(f"  [1/5] Computing LDE for {trace.n_registers} columns...")
        trace_lde = []
        for col in range(trace.n_registers):
            col_data = trace.trace_table[:, col]
            lde = self.compute_lde(col_data, blowup_factor=self.params.blowup_factor)
            trace_lde.append(lde)
        
        # Step 2: Commit to trace polynomials
        print(f"  [2/5] Committing to trace polynomials...")
        trace_commitment = self.CommitmentTree(trace_lde)
        transcript.append(b'trace_commitment', trace_commitment.root)
        
        # Step 3: Compute composition polynomial
        print(f"  [3/5] Computing composition polynomial...")
        alpha = transcript.challenge(b'alpha')
        composition_poly = self._compute_composition_polynomial(trace, trace_lde, alpha)
        
        # Step 4: FRI proof for composition polynomial
        print(f"  [4/5] Generating FRI proof...")
        fri_prover = self.FRIProver(self.params.__dict__)
        fri_proof = fri_prover.prove(composition_poly, transcript)
        
        # Step 5: Query phase
        print(f"  [5/5] Generating {self.params.n_queries} query responses...")
        query_indices = transcript.challenge_indices(
            count=self.params.n_queries,
            domain_size=len(composition_poly)
        )
        
        query_responses = []
        for idx in query_indices:
            response = {
                'index': idx,
                'trace_values': [int(col[idx]) for col in trace_lde],
                'composition_value': int(composition_poly[idx]),
                'auth_paths': trace_commitment.get_query_response(idx)
            }
            query_responses.append(response)
        
        return {
            'trace_commitment': trace_commitment.root,
            'fri_proof': fri_proof,
            'query_responses': query_responses,
            'composition_degree': len(composition_poly),
            'params': self.params.__dict__
        }
    
    def _compute_composition_polynomial(self, trace, trace_lde, alpha):
        """
        Compute composition polynomial that encodes all constraints.
        
        The composition polynomial combines:
        - Boundary constraints (initial/final state)
        - Transition constraints (state evolution)
        - MPT-specific constraints (path traversal, etc.)
        
        All combined with random linear combination using alpha.
        
        Args:
            trace: Original execution trace
            trace_lde: Low-degree extended trace columns
            alpha: Random challenge for linear combination
            
        Returns:
            Composition polynomial evaluations
        """
        from zkSTARK.circuits.mpt_circuit import MPTConstraintSystem
        from zkSTARK.field import field_add, field_mul, FIELD_PRIME_INT
        
        n = len(trace_lde[0])  # Extended domain size
        composition = np.zeros(n, dtype=np.uint64)
        
        # For simplicity, we create a basic composition polynomial
        # Full implementation would evaluate all constraints on extended domain
        
        # Simplified: just combine trace columns with random weights
        alpha_power = np.uint64(1)
        for col in trace_lde:
            for i in range(n):
                contribution = np.uint64(field_mul(alpha_power, col[i]))
                composition[i] = field_add(np.uint64(composition[i]), np.uint64(contribution))
            
            # Update alpha power
            alpha_power = np.uint64(field_mul(alpha_power, alpha))
        
        return composition
    
    def _validate_trace(self, trace) -> bool:
        """
        Validate execution trace meets MPT requirements.
        
        Args:
            trace: ExecutionTrace to validate
            
        Returns:
            True if trace is valid
        """
        from zkSTARK.circuits.mpt_circuit import MPTConstraintSystem
        
        # Check dimensions
        if trace.n_registers != 8:
            print(f"ERROR: MPT circuit requires 8 registers, got {trace.n_registers}")
            return False
        
        if trace.n_steps & (trace.n_steps - 1) != 0:
            print(f"ERROR: Trace length must be power of 2, got {trace.n_steps}")
            return False
        
        # Check constraints
        if not MPTConstraintSystem.verify_constraints(trace):
            print(f"ERROR: Constraint verification failed")
            return False
        
        return True
    
    def _calculate_proof_size(self, proof: Dict) -> int:
        """
        Calculate total proof size in bytes.
        
        Args:
            proof: STARK proof dictionary
            
        Returns:
            Estimated proof size in bytes
        """
        size = 0
        
        # Trace commitment root
        size += 32
        
        # FRI proof (estimate based on layers)
        if 'fri_proof' in proof and hasattr(proof['fri_proof'], 'layer_commitments'):
            size += len(proof['fri_proof'].layer_commitments) * 32
            size += len(proof['fri_proof'].query_responses) * 200  # ~200 bytes per query
        
        # Query responses
        size += len(proof.get('query_responses', [])) * 100
        
        return size
    
    def get_setup_params(self) -> Dict[str, Any]:
        """
        Get setup parameters for this prover.
        
        Returns:
            Dictionary of setup parameters
        """
        return {
            'field_modulus': self.params.field_modulus,
            'trace_columns': 8,
            'trace_length': self.trace_length,
            'security_params': self.params.__dict__
        }
    
    def proof_size(self, commitments, witness) -> int:
        size = 0
        for proof in commitments:
            size += proof.proof_size_bytes
        return size
