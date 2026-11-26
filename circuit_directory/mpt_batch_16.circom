pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/comparators.circom";
include "node_modules/circomlib/circuits/bitify.circom";

// Batched membership proof for the Poseidon MPT (field-native encoding, see
// zkSNARK/zk_encoder_decoder.py). Statement, for every i < NUM_KEYS:
//     the trie with root `root` contains a leaf whose full key is
//     (key_hi[i], key_lo[i]) and whose value is (val_len[i], val[i][0..3]).
// Leaves commit to their full key, so the path digits need no separate check:
// a hash chain from such a leaf to the root exists only if the leaf is in the trie.
//
// Node words: Leaf [1, rem, key_hi, key_lo, len, v0..v3]     (3 Poseidon batches)
//             Ext  [2, len, path_hi, path_lo, next]           (2 batches)
//             Branch [3, c0..c15, 0]                          (5 batches)

// ==============================================================================
// 1. Selector multiplexer: out = in[index] (index must be < N)
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
        sums[i+1] <== sums[i] + eqs[i].out * in[i];
    }
    out <== sums[N];
}

// ==============================================================================
// 2. Sponge: state_{b+1} = Poseidon(chunks[4b] + state_b, chunks[4b+1..4b+3]).
//    Matches merkle/hash.py:poseidon_hash_bytes. Exposes every intermediate state.
// ==============================================================================
template PoseidonSponge(NUM_BATCHES) {
    signal input chunks[4 * NUM_BATCHES];
    signal output states[NUM_BATCHES + 1];

    component hashers[NUM_BATCHES];
    states[0] <== 0;
    for (var i = 0; i < NUM_BATCHES; i++) {
        hashers[i] = Poseidon(4);
        hashers[i].inputs[0] <== chunks[4 * i] + states[i];
        for (var j = 1; j < 4; j++) {
            hashers[i].inputs[j] <== chunks[4 * i + j];
        }
        states[i+1] <== hashers[i].out;
    }
}

// ==============================================================================
// 3. One leaf-to-root path
// ==============================================================================
template VerifyMPTPath(MAX_DEPTH) {
    var LEAF_BATCHES = 3;
    var NODE_BATCHES = 5;
    var NODE_CHUNKS = 4 * NODE_BATCHES;

    // public
    signal input root;
    signal input key_hi;
    signal input key_lo;
    signal input val_len;
    signal input val[4];

    // private
    signal input actual_depth;                         // number of nodes above the leaf
    signal input leaf_chunks[4 * LEAF_BATCHES];
    signal input node_types[MAX_DEPTH];                // 0 = extension, 1 = branch
    signal input node_nibbles[MAX_DEPTH];              // child index (branch only)
    signal input node_chunks[MAX_DEPTH][NODE_CHUNKS];

    // Leaf: type tag, key and value are the public ones, padding is zero
    leaf_chunks[0] === 1;
    leaf_chunks[2] === key_hi;
    leaf_chunks[3] === key_lo;
    leaf_chunks[4] === val_len;
    for (var j = 0; j < 4; j++) {
        leaf_chunks[5 + j] === val[j];
    }
    for (var j = 9; j < 4 * LEAF_BATCHES; j++) {
        leaf_chunks[j] === 0;
    }

    component leaf_hasher = PoseidonSponge(LEAF_BATCHES);
    for (var j = 0; j < 4 * LEAF_BATCHES; j++) leaf_hasher.chunks[j] <== leaf_chunks[j];

    signal current[MAX_DEPTH + 1];
    current[0] <== leaf_hasher.states[LEAF_BATCHES];

    component depth_ok = LessEqThan(8);
    depth_ok.in[0] <== actual_depth;
    depth_ok.in[1] <== MAX_DEPTH;
    depth_ok.out === 1;

    component active[MAX_DEPTH];
    component nibble_bits[MAX_DEPTH];
    component child[MAX_DEPTH];
    component hasher[MAX_DEPTH];
    signal node_hash[MAX_DEPTH];
    signal target[MAX_DEPTH];
    signal type_nibble[MAX_DEPTH];

    for (var i = 0; i < MAX_DEPTH; i++) {
        active[i] = LessThan(8);
        active[i].in[0] <== i;
        active[i].in[1] <== actual_depth;

        // node type is boolean and matches the node's own tag (2 = ext, 3 = branch)
        node_types[i] * (node_types[i] - 1) === 0;
        active[i].out * (node_chunks[i][0] - 2 - node_types[i]) === 0;

        // child slot: next_ref (word 4) for an extension, word 1 + nibble for a branch
        nibble_bits[i] = Num2Bits(4);
        nibble_bits[i].in <== node_nibbles[i];
        type_nibble[i] <== node_types[i] * node_nibbles[i];
        target[i] <== 4 - 3 * node_types[i] + type_nibble[i];

        child[i] = Selector(NODE_CHUNKS);
        for (var j = 0; j < NODE_CHUNKS; j++) child[i].in[j] <== node_chunks[i][j];
        child[i].index <== target[i];
        active[i].out * (child[i].out - current[i]) === 0;

        // node hash over 2 batches (extension) or 5 batches (branch)
        hasher[i] = PoseidonSponge(NODE_BATCHES);
        for (var j = 0; j < NODE_CHUNKS; j++) hasher[i].chunks[j] <== node_chunks[i][j];
        node_hash[i] <== hasher[i].states[2] + node_types[i] * (hasher[i].states[5] - hasher[i].states[2]);

        current[i+1] <== current[i] + active[i].out * (node_hash[i] - current[i]);
    }

    current[MAX_DEPTH] === root;
}

// ==============================================================================
// 4. Batch of NUM_KEYS paths under one root
// ==============================================================================
template BatchedMPT(NUM_KEYS, MAX_DEPTH) {
    signal input root;
    signal input key_hi[NUM_KEYS];
    signal input key_lo[NUM_KEYS];
    signal input val_len[NUM_KEYS];
    signal input val[NUM_KEYS][4];

    signal input actual_depth[NUM_KEYS];
    signal input leaf_chunks[NUM_KEYS][12];
    signal input node_types[NUM_KEYS][MAX_DEPTH];
    signal input node_nibbles[NUM_KEYS][MAX_DEPTH];
    signal input node_chunks[NUM_KEYS][MAX_DEPTH][20];

    component paths[NUM_KEYS];
    for (var k = 0; k < NUM_KEYS; k++) {
        paths[k] = VerifyMPTPath(MAX_DEPTH);
        paths[k].root <== root;
        paths[k].key_hi <== key_hi[k];
        paths[k].key_lo <== key_lo[k];
        paths[k].val_len <== val_len[k];
        for (var j = 0; j < 4; j++) paths[k].val[j] <== val[k][j];
        paths[k].actual_depth <== actual_depth[k];
        for (var j = 0; j < 12; j++) paths[k].leaf_chunks[j] <== leaf_chunks[k][j];
        for (var d = 0; d < MAX_DEPTH; d++) {
            paths[k].node_types[d] <== node_types[k][d];
            paths[k].node_nibbles[d] <== node_nibbles[k][d];
            for (var j = 0; j < 20; j++) paths[k].node_chunks[d][j] <== node_chunks[k][d][j];
        }
    }
}

component main {public [root, key_hi, key_lo, val_len, val]} = BatchedMPT(16, 10);
