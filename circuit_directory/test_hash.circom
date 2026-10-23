pragma circom 2.1.6;
include "node_modules/circomlib/circuits/poseidon.circom";

// Testing a Poseidon hash of exactly 4 inputs
component main = Poseidon(4);