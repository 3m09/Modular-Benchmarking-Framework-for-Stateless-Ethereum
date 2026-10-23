pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

// ==============================================================================
// 1. Selector Multiplexer (Array Indexing with Signals)
// In ZK, you cannot do `array[signal]`. You must use a multiplexer.
// ==============================================================================
template Selector(N) {
    signal input in[N];
    signal input index;
    signal output out;

    component eqs[N];
    signal sums[N+1];
    sums[0] <== 0;

    for (var i = 0; i < N; i++) {
        eqs[i] = IsEqual();
        eqs[i].in[0] <== i;
        eqs[i].in[1] <== index;
        
        sums[i+1] <== sums[i] + (eqs[i].out * in[i]);
    }
    out <== sums[N];
}

// ==============================================================================
// 2. Batched Sponge Hash (Mirrors _poseidon_sponge_circuit)
// ==============================================================================
template PoseidonSponge(MAX_CHUNKS, MAX_BATCHES) {
    signal input chunks[MAX_CHUNKS];
    signal input actual_batches; // Provided by prover to know when to stop
    signal output out;

    var BATCH_SIZE = 4;
    
    component hashers[MAX_BATCHES];
    signal states[MAX_BATCHES + 1];
    states[0] <== 0;

    for (var i = 0; i < MAX_BATCHES; i++) {
        hashers[i] = Poseidon(BATCH_SIZE);
        for (var j = 0; j < BATCH_SIZE; j++) {
            var idx = i * BATCH_SIZE + j;
            
            // Add previous state to index 0 of the batch (Chaining)
            if (j == 0) {
                hashers[i].inputs[j] <== chunks[idx] + states[i];
            } else {
                hashers[i].inputs[j] <== chunks[idx];
            }
        }
        states[i+1] <== hashers[i].out;
    }

    // Dynamically select the final state based on actual_batches
    component state_selector = Selector(MAX_BATCHES + 1);
    for(var i = 0; i <= MAX_BATCHES; i++) {
        state_selector.in[i] <== states[i];
    }
    state_selector.index <== actual_batches;
    out <== state_selector.out;
}

// ==============================================================================
// 3. Main MPT Verification Circuit
// ==============================================================================
template VerifyMPTPath(MAX_DEPTH, MAX_CHUNKS) {
    var BATCH_SIZE = 4;
    var MAX_BATCHES = (MAX_CHUNKS + BATCH_SIZE - 1) \ BATCH_SIZE;

    // --- Public Inputs ---
    signal input root_pub;
    signal input length_pub;
    signal input val_pub_0;
    signal input val_pub_1;
    signal input val_pub_2;

    // --- Private Inputs ---
    signal input actual_depth; // How deep this specific path is
    
    // Leaf Data
    signal input leaf_chunks[MAX_CHUNKS];
    signal input leaf_batches;

    // Path Data (Bottom-Up: index 0 is parent of leaf)
    signal input node_types[MAX_DEPTH];     // 0 = Extension, 1 = Branch
    signal input node_nibbles[MAX_DEPTH];   // 0..15 for branch paths
    signal input node_chunks[MAX_DEPTH][MAX_CHUNKS];
    signal input node_batches[MAX_DEPTH];

    // ==========================================
    // STEP 1: Process Leaf
    // ==========================================
    // Constrain the leaf chunks to match our public values
    leaf_chunks[4] === length_pub;
    leaf_chunks[5] === val_pub_0;
    leaf_chunks[6] === val_pub_1;
    leaf_chunks[7] === val_pub_2;

    component leaf_hasher = PoseidonSponge(MAX_CHUNKS, MAX_BATCHES);
    for(var i=0; i<MAX_CHUNKS; i++) leaf_hasher.chunks[i] <== leaf_chunks[i];
    leaf_hasher.actual_batches <== leaf_batches;

    // ==========================================
    // STEP 2: Bottom-Up Traversal
    // ==========================================
    signal current_hash[MAX_DEPTH + 1];
    current_hash[0] <== leaf_hasher.out;

    component node_hashers[MAX_DEPTH];
    component target_selector[MAX_DEPTH];
    component is_active_depth[MAX_DEPTH];

    // FIX: Declare signals as arrays OUTSIDE the loop
    signal target_idx[MAX_DEPTH];
    signal hash_diff[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        // A. Calculate where the child hash should be in this parent node
        // Equation: target = 4 - 3*type + type*nibble
        // If type=0 (Ext), target = 4. If type=1 (Branch), target = 1 + nibble.
        target_idx[i] <== 4 - (3 * node_types[i]) + (node_types[i] * node_nibbles[i]);

        // B. Assert the child hash matches the slot in the parent chunks
        target_selector[i] = Selector(MAX_CHUNKS);
        for(var j=0; j<MAX_CHUNKS; j++) {
            target_selector[i].in[j] <== node_chunks[i][j];
        }
        target_selector[i].index <== target_idx[i];
        
        // Only enforce this constraint if we haven't exceeded the actual depth
        is_active_depth[i] = LessThan(8);
        is_active_depth[i].in[0] <== i;
        is_active_depth[i].in[1] <== actual_depth;
        
        // (If active, diff must be 0)
        hash_diff[i] <== target_selector[i].out - current_hash[i];
        is_active_depth[i].out * hash_diff[i] === 0;

        // C. Hash the parent node
        node_hashers[i] = PoseidonSponge(MAX_CHUNKS, MAX_BATCHES);
        for(var j=0; j<MAX_CHUNKS; j++) {
            node_hashers[i].chunks[j] <== node_chunks[i][j];
        }
        node_hashers[i].actual_batches <== node_batches[i];

        // D. Update current hash (If padded dummy layer, pass old hash forward)
        current_hash[i+1] <== is_active_depth[i].out * (node_hashers[i].out - current_hash[i]) + current_hash[i];
    }

    // ==========================================
    // STEP 3: Root Assertion
    // ==========================================
    current_hash[MAX_DEPTH] === root_pub;
}

// Compile with MAX_DEPTH=10 and MAX_CHUNKS=40 (Adjust if your branch nodes are larger)
component main {public [root_pub, length_pub, val_pub_0, val_pub_1, val_pub_2]} = VerifyMPTPath(10, 40);