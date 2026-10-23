# Stateless Ethereum — State Proof Benchmarks

Thesis codebase comparing witness/proof schemes for stateless Ethereum clients:

| Tree | Hash / commitment | Provers / verifiers |
|------|-------------------|---------------------|
| Merkle Patricia Trie (`merkle`) | keccak or poseidon | `merkle`, `merkle_optimized`, `zkstarkmerkle`, `zksnarkmerkle` |
| Verkle tree (`verkle`) | KZG over BLS12-381 (`verkle_kzg` setup) | `verkle`, `verkle_optimized`, `verkle_multiproof`, `verkle_multiproof_optimized` |

Every run measures proof size, proving time and verification time and appends one row to `results_latest.csv`.
See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full pipeline.

## Repository layout

```
.
├── prove_verify.py                 # one prove+verify run, configured by proving_setup.json
├── generate_tree.py                # build one tree, configured by tree_generation_setup.json
├── run_experiment.py               # build trees + prove/verify sweep, configured by experiment.json
├── automate_prove_verify.py        # sweep num_keys for trees (uses proving_setup.json as template)
├── automate_prove_verify_v2.py     # sweep trees x prover/verifier pairs x num_keys (self-contained)
├── test_scheme.py                  # in-memory sanity check, configured by global_setup.json
├── get_eth_data.py                 # fetch real account proofs from mainnet (Infura)
│
├── *.json (root)                   # run configs + datasets (data.json, random_data.json)
├── results_latest.csv              # all benchmark results
├── tree_ids.txt                    # ids of generated trees (tree_storage/<id>)
│
├── tree/  prover/  verifier/  setups/   # implementations, auto-registered via registry/
├── registry/                       # TREE / PROVER / VERIFIER / SETUP registries
├── merkle/                         # MPT nodes, nibble paths, hashing (+ poseidon_worker.js)
├── verkle/                         # KZG commitments, serialization, field utils
├── zkSTARK/                        # STARK prover/verifier (FRI, field, transcript, MPT circuit)
├── zkSNARK/                        # SNARK encoding helpers
├── circuit_directory/              # Circom circuits (mpt*.circom) + verification_keys/
│
├── experiments/                    # exp_N_plot.py + the run lists (expN.txt) used for thesis plots
├── scripts/                        # standalone helpers (data generators, hash debug scripts)
├── data/                           # raw mainnet key/value snapshot
└── docs/                           # ARCHITECTURE.md, presentation/ (LaTeX beamer)
```

> All scripts use paths relative to the repository root — **always run them from the repo root.**

## Setup

### 1. Python (3.11)

```bash
uv venv --python 3.11 && source .venv/bin/activate
uv pip install -r requirements-lock.txt     # exact environment used for the thesis
# (requirements.txt is the original, minimal list)
```
`plyvel` needs the LevelDB headers (`sudo apt install libleveldb-dev`).

### 2. Node.js (Poseidon hashing for `HASH_FN: "poseidon"`, SNARK verification)

```bash
npm install                     # circomlibjs + snarkjs (used by merkle/poseidon_worker.js)
npm install -g snarkjs          # zksnarkmerkle verifier calls `snarkjs` from PATH
```

### 3. Environment variables (only for fetching mainnet data)

```bash
cp .env.example .env            # then set INFURA_API_KEY
```

### 4. zk-SNARK artifacts (only for `zksnarkmerkle`)

These are large / machine-specific and are **not in git**. The prover expects:

| Path | What |
|------|------|
| `circuit_directory/mpt_batch_16_cpp/mpt_batch_16` | Circom C++ witness generator |
| `mpt_batch_16.zkey` | Groth16 proving key |
| `verification_key_batch_16.json` | Groth16 verification key (tracked) |
| `rapidsnark/package/bin/prover` | RapidSnark prover binary |

Rebuild them with:

```bash
# circuit -> witness generator
(cd circuit_directory && npm install)                   # circomlib
circom circuit_directory/mpt_batch_16.circom --r1cs --c --sym -o circuit_directory
make -C circuit_directory/mpt_batch_16_cpp

# trusted setup: pick a Hermez powers-of-tau file with 2^N >= the constraint count
snarkjs r1cs info circuit_directory/mpt_batch_16.r1cs
snarkjs groth16 setup circuit_directory/mpt_batch_16.r1cs powersOfTau28_hez_final_<N>.ptau mpt_batch_16.zkey
snarkjs zkey export verificationkey mpt_batch_16.zkey verification_key_batch_16.json

# rapidsnark: clone iden3/rapidsnark (thesis used commit 81eddf1) into ./rapidsnark
# and follow its README to build; the code expects rapidsnark/package/bin/prover
git clone https://github.com/iden3/rapidsnark.git
```

## Usage

### Generate a tree

Edit `tree_generation_setup.json` (`TREE_TYPE`, `HASH_FN`, `SETUP_TYPE`, `WIDTH`, `NUM_KEYS`), then:

```bash
python generate_tree.py
```
The tree is stored in `tree_storage/<uuid>/` (LevelDB + `tree_info.json`) and the id is appended to `tree_ids.txt`.
Merkle trees read keys from `data.json`; verkle trees from `random_data.json`.

### Prove + verify once

Edit `proving_setup.json` (`TREE_ID`, `PROVER_TYPE`, `VERIFIER_TYPE`, `NUM_KEYS_TO_PROVE`, …), then:

```bash
python prove_verify.py
```

### Sweeps

```bash
# num_keys sweep; rewrites proving_setup.json per run
python automate_prove_verify.py            # input: automate_prove_verify_input.json

# trees x prover/verifier pairs x num_keys; never touches proving_setup.json
python automate_prove_verify_v2.py [input.json] [--keep-going]   # default input: automate_prove_verify_v2_input.json

# build trees and benchmark them in one go
python run_experiment.py                   # input: experiment.json
```

`automate_prove_verify_v2_input.json` format (tree params default to `tree_storage/<id>/tree_info.json`):

```json
[
  {
    "id": "<tree id>",
    "num_keys": [1, 2, 4, 8],
    "prover_verifier": [
      {"prover": "merkle", "verifier": "merkle"},
      {"prover": "zkstarkmerkle", "verifier": "zkstarkmerkle", "num_keys": [1, 2]}
    ]
  }
]
```

### Plots

Each `experiments/expN.txt` lists the runs behind one thesis figure. From the repo root:

```bash
python experiments/exp_1_plot.py experiments/exp1.txt      # reads results_latest.csv
python experiments/exp_3_plot.py experiments/exp3.txt --strategy average
```

### Helper scripts

```bash
python scripts/random_data_generator.py      # synthetic key/value data (default: data/random_kv.json)
python scripts/real_eth_data_generator.py    # mainnet state sample -> ethereum_real_state_trie.json (needs .env)
python test_scheme.py                        # quick in-memory check (global_setup.json)
```
