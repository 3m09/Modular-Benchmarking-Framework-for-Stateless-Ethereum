pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";

// ==============================================================================
// 1. Selector Multiplexer
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
// 2. Batched Sponge Hash
// ==============================================================================
template PoseidonSponge(MAX_CHUNKS, MAX_BATCHES) {
    signal input chunks[MAX_CHUNKS];
    signal input actual_batches;
    signal output out;

    var BATCH_SIZE = 4;
    
    component hashers[MAX_BATCHES];
    signal states[MAX_BATCHES + 1];
    states[0] <== 0;

    for (var i = 0; i < MAX_BATCHES; i++) {
        hashers[i] = Poseidon(BATCH_SIZE);
        for (var j = 0; j < BATCH_SIZE; j++) {
            var idx = i * BATCH_SIZE + j;
            
            if (j == 0) {
                hashers[i].inputs[j] <== chunks[idx] + states[i];
            } else {
                hashers[i].inputs[j] <== chunks[idx];
            }
        }
        states[i+1] <== hashers[i].out;
    }

    component state_selector = Selector(MAX_BATCHES + 1);
    for(var i = 0; i <= MAX_BATCHES; i++) {
        state_selector.in[i] <== states[i];
    }
    state_selector.index <== actual_batches;
    out <== state_selector.out;
}

// ==============================================================================
// 3. Single MPT Path Verifier
// ==============================================================================
template VerifyMPTPath(MAX_DEPTH, MAX_CHUNKS) {
    var BATCH_SIZE = 4;
    var MAX_BATCHES = (MAX_CHUNKS + BATCH_SIZE - 1) \ BATCH_SIZE;

    signal input root_pub;
    signal input length_pub;
    signal input val_pub_0;
    signal input val_pub_1;
    signal input val_pub_2;

    signal input actual_depth;
    signal input leaf_chunks[MAX_CHUNKS];
    signal input leaf_batches;

    signal input node_types[MAX_DEPTH];
    signal input node_nibbles[MAX_DEPTH];
    signal input node_chunks[MAX_DEPTH][MAX_CHUNKS];
    signal input node_batches[MAX_DEPTH];

    leaf_chunks[4] === length_pub;
    leaf_chunks[5] === val_pub_0;
    leaf_chunks[6] === val_pub_1;
    leaf_chunks[7] === val_pub_2;

    component leaf_hasher = PoseidonSponge(MAX_CHUNKS, MAX_BATCHES);
    for(var i=0; i<MAX_CHUNKS; i++) leaf_hasher.chunks[i] <== leaf_chunks[i];
    leaf_hasher.actual_batches <== leaf_batches;

    signal current_hash[MAX_DEPTH + 1];
    current_hash[0] <== leaf_hasher.out;

    component node_hashers[MAX_DEPTH];
    component target_selector[MAX_DEPTH];
    component is_active_depth[MAX_DEPTH];

    signal target_idx[MAX_DEPTH];
    signal hash_diff[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        target_idx[i] <== 4 - (3 * node_types[i]) + (node_types[i] * node_nibbles[i]);

        target_selector[i] = Selector(MAX_CHUNKS);
        for(var j=0; j<MAX_CHUNKS; j++) {
            target_selector[i].in[j] <== node_chunks[i][j];
        }
        target_selector[i].index <== target_idx[i];
        
        is_active_depth[i] = LessThan(8);
        is_active_depth[i].in[0] <== i;
        is_active_depth[i].in[1] <== actual_depth;
        
        hash_diff[i] <== target_selector[i].out - current_hash[i];
        is_active_depth[i].out * hash_diff[i] === 0;

        node_hashers[i] = PoseidonSponge(MAX_CHUNKS, MAX_BATCHES);
        for(var j=0; j<MAX_CHUNKS; j++) {
            node_hashers[i].chunks[j] <== node_chunks[i][j];
        }
        node_hashers[i].actual_batches <== node_batches[i];

        current_hash[i+1] <== is_active_depth[i].out * (node_hashers[i].out - current_hash[i]) + current_hash[i];
    }

    current_hash[MAX_DEPTH] === root_pub;
}

// ==============================================================================
// 4. Batched Wrapper (New)
// ==============================================================================
template BatchedMPT(NUM_KEYS, MAX_DEPTH, MAX_CHUNKS) {
    signal input root_pub[NUM_KEYS];
    signal input length_pub[NUM_KEYS];
    signal input val_pub_0[NUM_KEYS];
    signal input val_pub_1[NUM_KEYS];
    signal input val_pub_2[NUM_KEYS];
    
    signal input actual_depth[NUM_KEYS];
    signal input leaf_chunks[NUM_KEYS][MAX_CHUNKS];
    signal input leaf_batches[NUM_KEYS];
    
    signal input node_types[NUM_KEYS][MAX_DEPTH];
    signal input node_nibbles[NUM_KEYS][MAX_DEPTH];
    signal input node_chunks[NUM_KEYS][MAX_DEPTH][MAX_CHUNKS];
    signal input node_batches[NUM_KEYS][MAX_DEPTH];

    component verifiers[NUM_KEYS];

    for (var i = 0; i < NUM_KEYS; i++) {
        verifiers[i] = VerifyMPTPath(MAX_DEPTH, MAX_CHUNKS);
        
        verifiers[i].root_pub <== root_pub[i];
        verifiers[i].length_pub <== length_pub[i];
        verifiers[i].val_pub_0 <== val_pub_0[i];
        verifiers[i].val_pub_1 <== val_pub_1[i];
        verifiers[i].val_pub_2 <== val_pub_2[i];
        
        verifiers[i].actual_depth <== actual_depth[i];
        verifiers[i].leaf_batches <== leaf_batches[i];
        
        for (var j = 0; j < MAX_CHUNKS; j++) {
            verifiers[i].leaf_chunks[j] <== leaf_chunks[i][j];
        }
        
        for (var d = 0; d < MAX_DEPTH; d++) {
            verifiers[i].node_types[d] <== node_types[i][d];
            verifiers[i].node_nibbles[d] <== node_nibbles[i][d];
            verifiers[i].node_batches[d] <== node_batches[i][d];
            for (var j = 0; j < MAX_CHUNKS; j++) {
                verifiers[i].node_chunks[d][j] <== node_chunks[i][d][j];
            }
        }
    }
}

// ------------------------------------------------------------------------------
// CHANGE NUM_KEYS HERE (e.g., 4 or 16) TO MATCH YOUR PYTHON SCRIPT
// ------------------------------------------------------------------------------
component main {public [root_pub, length_pub, val_pub_0, val_pub_1, val_pub_2]} = BatchedMPT(16, 10, 40);