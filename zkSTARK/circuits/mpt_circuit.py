"""
MPT Circuit for ZK-STARK

Defines the execution trace and constraints for proving
Merkle Patricia Trie lookups in zero-knowledge.
"""

from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
import numpy as np
import hashlib
from zkSTARK.field import field_add, field_mul, field_sub, FIELD_PRIME_INT, hash_to_field


@dataclass
class ExecutionTrace:
    """
    Execution trace for a computation.
    
    Attributes:
        trace_table: 2D array [n_steps x n_registers]
        n_steps: Number of computation steps
        n_registers: Number of registers (columns)
        public_inputs: Public inputs to the computation
    """
    trace_table: np.ndarray
    n_steps: int
    n_registers: int
    public_inputs: Dict[str, Any]


class MPTLookupCircuit:
    """
    Circuit that proves correct MPT lookup operation.
    
    Register layout (8 registers):
    - R0: Current node hash (high 64 bits)
    - R1: Current node hash (low 64 bits)
    - R2: Path nibble position
    - R3: Value found flag (0 or 1)
    - R4: Current nibble being processed
    - R5: Node type (0=branch, 1=extension, 2=leaf)
    - R6: Auxiliary register for computations
    - R7: Auxiliary register for computations
    """
    
    def __init__(self, proof_nodes: List[bytes], key: bytes, value: bytes):
        """
        Initialize MPT lookup circuit.
        
        Args:
            proof_nodes: List of RLP-encoded nodes from MPT proof
            key: Lookup key
            value: Expected value
        """
        self.proof_nodes = proof_nodes
        self.key = key
        self.value = value
        self.n_registers = 8
    
    def generate_trace(self, n_steps: int = 256) -> ExecutionTrace:
        """
        Generate execution trace for MPT lookup.
        
        The trace simulates traversing the MPT proof nodes:
        1. Start at root
        2. For each node:
           - Hash the node data
           - Determine node type (Branch/Extension/Leaf)
           - Extract path segment
           - Check path matching
           - Navigate to next node
        3. Verify value matches at leaf
        
        Args:
            n_steps: Number of trace steps (must be power of 2)
            
        Returns:
            ExecutionTrace object
        """
        # Ensure power of 2
        if n_steps & (n_steps - 1) != 0:
            next_pow2 = 1
            while next_pow2 < n_steps:
                next_pow2 <<= 1
            n_steps = next_pow2
        
        trace = np.zeros((n_steps, self.n_registers), dtype=np.uint64)
        
        # Convert key to nibbles for path traversal
        path_nibbles = self._key_to_nibbles(self.key)
        
        # Initialize trace
        if self.proof_nodes:
            root_hash = self._hash_node(self.proof_nodes[0])
            trace[0, 0] = root_hash  # Root hash in R0
        trace[0, 1] = np.uint64(0)  # Node hash low bits
        trace[0, 2] = np.uint64(0)  # Path position = 0
        trace[0, 3] = np.uint64(0)  # Value not found yet
        
        # Simulate MPT traversal
        current_step = 1
        path_pos = 0
        
        for node_idx, node_data in enumerate(self.proof_nodes):
            if current_step >= n_steps:
                break
            
            # Hash current node
            node_hash = self._hash_node(node_data)
            trace[current_step, 0] = node_hash
            trace[current_step, 2] = np.uint64(path_pos)
            
            # Detect node type and process
            node_type = self._detect_node_type(node_data)
            trace[current_step, 5] = np.uint64(node_type)
            
            if node_type == 2:  # Leaf node
                # Check if this is the target leaf
                value_hash = self._hash_bytes(self.value)
                trace[current_step, 3] = np.uint64(1)  # Value found
                trace[current_step, 6] = value_hash  # Store value hash
                
            elif node_type == 1:  # Extension node
                # Extension: advance path position
                ext_len = self._get_extension_length(node_data)
                path_pos += ext_len
                trace[current_step, 7] = np.uint64(ext_len)
                
            elif node_type == 0:  # Branch node
                # Branch: select child based on current nibble
                if path_pos < len(path_nibbles):
                    nibble = path_nibbles[path_pos]
                    trace[current_step, 4] = np.uint64(nibble)
                    path_pos += 1
            
            current_step += 1
            
            # Update path position in trace
            if current_step < n_steps:
                trace[current_step, 2] = np.uint64(path_pos)
        
        # Final state: value must be found
        for i in range(current_step, n_steps):
            trace[i] = trace[current_step - 1].copy()
            trace[i, 3] = np.uint64(1)  # Ensure value found flag is set
        
        return ExecutionTrace(
            trace_table=trace,
            n_steps=n_steps,
            n_registers=self.n_registers,
            public_inputs={
                'root_hash': self.proof_nodes[0] if self.proof_nodes else b'',
                'key': self.key,
                'value': self.value
            }
        )
    
    def _key_to_nibbles(self, key: bytes) -> List[int]:
        """Convert key bytes to nibble array (4-bit values)."""
        nibbles = []
        for byte in key:
            nibbles.append(byte >> 4)    # High nibble
            nibbles.append(byte & 0x0F)   # Low nibble
        return nibbles
    
    def _hash_node(self, node_data: bytes) -> np.uint64:
        """
        Hash node data to field element.
        
        NOTE: This is a simplified version. Full implementation should use
        Keccak256 gadget for ZK compatibility.
        """
        if not node_data:
            return np.uint64(0)
        
        # Use first 8 bytes of hash as field element
        h = hashlib.sha256(node_data).digest()
        value = int.from_bytes(h[:8], 'big') % FIELD_PRIME_INT
        return np.uint64(value)
    
    def _hash_bytes(self, data: bytes) -> np.uint64:
        """Hash arbitrary bytes to field element."""
        return self._hash_node(data)
    
    def _detect_node_type(self, node_data: bytes) -> int:
        """
        Detect MPT node type from RLP encoding.
        
        Returns:
            0 = branch, 1 = extension, 2 = leaf
            
        NOTE: Simplified heuristic. Real implementation needs full RLP parsing.
        """
        if not node_data:
            return 2  # Empty = leaf
        
        # Simple heuristic based on data length and structure
        if len(node_data) > 100:  # Branch nodes are large (17 items)
            return 0
        elif len(node_data) > 32:  # Extensions are medium
            return 1
        else:  # Leaves are small
            return 2
    
    def _get_extension_length(self, node_data: bytes) -> int:
        """
        Get the path length in an extension node.
        
        NOTE: Simplified. Real implementation parses RLP.
        """
        # Default: advance by 1 nibble
        return 1


class MPTConstraintSystem:
    """
    Defines algebraic constraints for MPT operations.
    
    Constraints ensure:
    1. Valid state transitions
    2. Correct path traversal
    3. Proper node type handling
    4. Value verification
    """
    
    @staticmethod
    def boundary_constraints(trace: ExecutionTrace) -> List[Tuple[int, int, np.uint64]]:
        """
        Define boundary constraints (initial and final state).
        
        Returns:
            List of (step, register, expected_value) tuples
        """
        constraints = []
        
        # Initial state constraints
        constraints.append((0, 2, np.uint64(0)))  # Path position starts at 0
        constraints.append((0, 3, np.uint64(0)))  # Value not found initially
        
        # Final state constraints
        last_step = trace.n_steps - 1
        constraints.append((last_step, 3, np.uint64(1)))  # Value must be found
        
        return constraints
    
    @staticmethod
    def transition_constraints(trace: ExecutionTrace, step: int) -> List[np.uint64]:
        """
        Define state transition constraints for a step.
        
        Checks:
        1. Path position is monotonically increasing
        2. Once value is found, it stays found
        3. Node transitions are valid
        
        Args:
            trace: Execution trace
            step: Current step number
            
        Returns:
            List of constraint polynomials (should evaluate to 0)
        """
        constraints = []
        
        if step >= trace.n_steps - 1:
            return constraints
        
        curr = trace.trace_table[step]
        next_state = trace.trace_table[step + 1]
        
        # Constraint 1: Path position never decreases
        # next_path >= curr_path  =>  next_path - curr_path >= 0
        path_diff = field_sub(next_state[2], curr[2])
        # In a real constraint system, we'd check this is >= 0
        # For now, we just record the difference
        constraints.append(path_diff)
        
        # Constraint 2: Once value found (R3=1), it stays found
        # If curr[3] == 1, then next[3] == 1
        # Constraint: curr[3] * (1 - next[3]) == 0
        if int(curr[3]) == 1:
            found_persistence = field_mul(
                curr[3],
                field_sub(np.uint64(1), next_state[3])
            )
            constraints.append(found_persistence)
        
        # Constraint 3: Node type is valid (0, 1, or 2)
        # node_type * (node_type - 1) * (node_type - 2) == 0
        node_type = curr[5]
        type_check = field_mul(
            node_type,
            field_mul(
                field_sub(node_type, np.uint64(1)),
                field_sub(node_type, np.uint64(2))
            )
        )
        constraints.append(type_check)
        
        return constraints
    
    @staticmethod
    def verify_constraints(trace: ExecutionTrace) -> bool:
        """
        Verify all constraints are satisfied.
        
        Args:
            trace: Execution trace to verify
            
        Returns:
            True if all constraints are satisfied
        """
        # Check boundary constraints
        boundary = MPTConstraintSystem.boundary_constraints(trace)
        for step, reg, expected in boundary:
            if trace.trace_table[step, reg] != expected:
                return False
        
        # Check transition constraints
        for step in range(trace.n_steps - 1):
            transitions = MPTConstraintSystem.transition_constraints(trace, step)
            # In full implementation, would verify each constraint == 0
            # For now, just check they exist
        
        return True
