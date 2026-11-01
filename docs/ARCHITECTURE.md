# Codebase Architecture

## Phase 0: Data Ingestion

```
[Ethereum Mainnet]
        │
        │  eth_getProof() per address
        ▼
  Key   = keccak256(address)       [32 bytes]
  Value = RLP([nonce, balance, storageRoot, codeHash])
        │
        ▼
  {hex key → hex RLP value} stored to disk
```

---

## Phase 1: Tree Generation

```
Configuration
{TREE_TYPE, HASH_FN, SETUP_TYPE, WIDTH, KEY_LENGTH, SECRET, NUM_KEYS}
        │
        ├─► Cryptographic Setup
        │   ┌──────────────────────────────────────────┐
        │   │  KZG  • BLS12-381 SRS (powers of τ·G1/G2) │
        │   │       • Lagrange polynomials              │
        │   │       • Root of unity for evaluation domain│
        │   │  IPA  • G[] generators, blinding factor H │
        │   │  None • (Merkle needs no setup)           │
        │   └──────────────────────────────────────────┘
        │
        └─► Tree Construction
            ┌────────────────────────────────────────────────────┐
            │  Merkle Patricia Trie                              │
            │   • Hex-nibble Patricia trie                       │
            │   • Nodes: Leaf / Extension / Branch               │
            │   • Hash: keccak256 OR poseidon                    │
            │                                                    │
            │  Poseidon Merkle Patricia Trie                     │
            │   • Same structure, Poseidon hash throughout       │
            │   • Required for zkSNARK arithmetisation           │
            │                                                    │
            │  Verkle Tree                                       │
            │   • n-ary tree (configurable width)                │
            │   • Each node: KZG commit over child values        │
            │   • Node hash = field element of commitment point  │
            └────────────────────────────────────────────────────┘
                      │
                      │  Insert all NUM_KEYS key→value pairs
                      ▼
             Persisted tree (LevelDB) + root reference saved to disk
```

---

## Phase 2: Proving & Verification

```
Configuration
{TREE_TYPE, TREE_ID, PROVER_TYPE, VERIFIER_TYPE, NUM_KEYS_TO_PROVE}
        │
        ├── Reconstruct setup + reload tree from disk
        └── Randomly sample NUM_KEYS_TO_PROVE keys
                  │
                  ▼
               PROVING
         ┌────────────────────────────────────────────────────┐
         │  Merkle (standard)                                 │
         │   • Collect root-to-leaf RLP node path per key     │
         │   • Witness = root hash                            │
         │                                                    │
         │  Merkle (optimized)                                │
         │   • Same paths but shared nodes deduplicated       │
         │   • Proof = unique node set + per-key index paths  │
         │                                                    │
         │  Verkle (standard)                                 │
         │   • Generate individual KZG openings for each key  │
         │   • Proof = array of individual G1 witness points  │
         │                                                    │
         │  Verkle (Multiproof)                               │
         │   • Derive randomness r via Fiat-Shamir            │
         │   • Aggregate KZG quotient polynomials per opening │
         │   • Single G1 elliptic-curve point proves all keys │
         │                                                    │
         │  zkSNARK (Groth16 / Poseidon)                      │
         │   • Compile R1CS & C++ witness via Circom          │
         │   • In-circuit Poseidon sponge: leaf → root        │
         │   • Output: WTNS + Groth16 JSON proof (RapidSnark) │
         │                                                    │
         │  zkSTARK (RISC Zero composite)                     │
         │   • Private RLP path enters Rust guest             │
         │   • Guest checks Keccak/RLP/path/value             │
         │   • One real receipt per key; count its bytes      │
         └────────────────────────────────────────────────────┘
                  │
                  │  (proof object, proof size in bytes)
                  ▼
            VERIFICATION
         ┌────────────────────────────────────────────────────┐
         │  Merkle (standard)                                 │
         │   • Recompute hash-chain from leaf to root         │
         │   • Check final hash == claimed root               │
         │                                                    │
         │  Merkle (optimized)                                │
         │   • Map deduplicated nodes to key-specific paths   │
         │   • Recompute root hash and check against claim    │
         │                                                    │
         │  Verkle (standard)                                 │
         │   • Verify individual KZG openings per key         │
         │   • Perform pairing check per key: e(C-yG, H) == e(W, S)│
         │                                                    │
         │  Verkle (Multiproof)                               │
         │   • Recompute r (same Fiat-Shamir as prover)       │
         │   • Pairing product check: e(C−y·G1, r^i) per      │
         │     opening, against global witness W              │
         │                                                    │
         │  zkSNARK (Groth16)                                 │
         │   • snarkjs: trusted setup → prove → verify        │
         │   • Pass/fail: "The proof is valid"                │
         │                                                    │
         │  zkSTARK (RISC Zero composite)                     │
         │   • Check receipt and compiled guest image ID      │
         │   • Bind journal to exact root, key, value         │
         └────────────────────────────────────────────────────┘                       │
                  ▼
    {proving_time, verification_time, proof_size} → results_latest.csv
```

---

## Proof Scheme Matrix

| Scheme | Tree type | Crypto primitive | Proof structure | Verification |
|---|---|---|---|---|
| Merkle (standard) | MPT (keccak) | Hash chain | RLP node list per key | Hash re-derivation |
| Merkle (optimized) | MPT (keccak) | Hash chain | Deduplicated node set + index paths | Hash re-derivation w/ routing |
| Verkle (standard) | Verkle (KZG) | BLS12-381 pairings | Array of individual G1 witnesses | Individual pairing checks |
| Verkle (Multiproof)| Verkle (KZG) | BLS12-381 pairings | Single G1 witness + per-node openings | Pairing product check |
| zkSNARK | Batched MPT (Poseidon) | Circom R1CS | C++ Witness + RapidSnark JSON Proof | snarkjs verify |
| zkSTARK | Hexary MPT (Keccak) | RISC Zero composite ZK-STARK | One receipt per key; private RLP path | Receipt/image verification and exact public-input match |

The old `zkSTARK/` Python modules are retained for reference but are not the
active `zkstarkmerkle` backend. See the branch README for the fix and test steps.
