# Stateless Ethereum — State Proof Benchmarks

## ZK-STARK fix on `zkstark-private-mpt-fix`

The previous Python `zkstarkmerkle` pipeline produced a FRI proof over a trace
that did **not** enforce the claimed Ethereum MPT lookup: it used a truncated
SHA-256 surrogate and incomplete node/path constraints. Its verifier did not
bind the proof to the caller's root, key, and value. Passing those tests was
therefore not evidence of a valid MPT ZK-STARK proof.

This branch replaces the active `zkstarkmerkle` backend with a pinned RISC Zero
3.0.6 **composite ZK-STARK receipt**. The Rust guest checks RLP node structure,
compact paths, Keccak-256 hashes, inline/hashed child links, and terminal value
against the claimed root and key. MPT nodes enter as private guest input; the
public journal contains the root, key, and value. The host verifies the guest
image ID and exact journal statement and rejects fake or non-composite
receipts. The Python adapter fails closed when the host is missing or rejects a
proof. Proof size is measured from serialized receipt bytes, not estimated.
The old `zkSTARK/` modules remain in the repository but are no longer the
registered `zkstarkmerkle` prover/verifier.

Supported scope: width-16 Keccak MPT membership with keys in their stored trie
form (`secure=False`). The implementation emits one receipt per key; it does
not provide batch aggregation or non-membership proofs.

### Reproduce the fix on another machine

Run these commands from the repository root. On Ubuntu, install native build
dependencies, Rust/Cargo, Node.js, and the [official RISC Zero `rzup`
installer](https://dev.risczero.com/zkvm/quickstart) first:

```bash
sudo apt-get install build-essential pkg-config libleveldb-dev python3.11-venv
curl -L https://risczero.com/install | bash
rzup install rust 1.97.0
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
npm ci
CARGO_BUILD_JOBS=2 cargo build --locked --manifest-path zkstark_risc0/Cargo.toml -p mpt_zkstark_host --release
```

The `curl` command is the upstream install method; inspect it before running
if your environment requires that. Host Rust 1.90.0 and RISC Zero guest Rust
1.97.0 were used for the successful build. The host binary is expected at
`zkstark_risc0/target/release/mpt_zkstark_host`; set `STARK_RISC0_HOST` only if
you build it elsewhere. The first optimized build can take many minutes and
needs substantial RAM and disk space. No new Python packages were added:
`requirements.txt` and `requirements-lock.txt` cover Python, while Rust crates
are pinned in `zkstark_risc0/Cargo.lock`. `npm ci` is needed because the tree
module starts a Poseidon worker even when these tests use Keccak.

Then run the native MPT tests, the adapter tests, and real-proof tests:

```bash
cargo test --locked --manifest-path zkstark_risc0/Cargo.toml -p mpt_zkstark_core --lib
.venv/bin/python -m unittest discover -s tests -p 'test_zkstark_adapter.py' -v
RUN_ZKSTARK_E2E=1 .venv/bin/python -m unittest discover -s tests -p 'test_zkstark_e2e.py' -v
```

The tests passed here: five Rust MPT tests, three Python adapter tests, and two
real-receipt tests (single leaf and extension/branch/leaf). Changed root, key,
and value were rejected. The single-leaf JSON receipt was about 568 kB; a
single local proving run took about 7.9 seconds on this machine. These are
examples, not five-run benchmark averages. Local Python tests used 3.10.12;
the partner's Python 3.11 lockfile installation still needs confirmation.
Larger trees, key batches, and
full experiment sweeps remain untested. Historical `zkstarkmerkle` result rows
used estimated sizes from the old implementation and must not be reported as
measurements of this backend. Rerun and record new experiments before updating
the paper. Dev mode is disabled in the host and must not be used for results.

Thesis codebase comparing witness/proof schemes for stateless Ethereum clients:

| Tree | Hash / commitment | Provers / verifiers |
|------|-------------------|---------------------|
| Merkle Patricia Trie (`merkle`), width 2/4/16/256 | keccak | `merkle`, `merkle_optimized`, `zkstarkmerkle` (width 16 only) |
| Merkle Patricia Trie (`merkle`), width 16 | poseidon | `zksnarkmerkle` |
| EIP-6800 Verkle tree (`verkle_eip6800`), width 16-256 | KZG over BLS12-381 (`verkle_kzg` setup) | `verkle_eip6800` |

All backends read the same mainnet accounts from `data.json`.
Every run measures proof size, proving time and verification time.
The paper's results come from `benchmark.py` (see "Paper experiments" below), which writes
`results/paper_results.csv`. `results_latest.csv` holds the older single-run thesis results and is kept only for reference.

### Changes for the paper (Nov 2026)

* **MPT width is real.** `tree/merkle_tree.py` now uses `WIDTH` for the key digits
  (log2(W) bits) and for the branch arity. Earlier, every "width" built the same hexary trie.
  Non-hex paths use a bit-packed encoding. The verifiers take the arity from the proof and check it.
* **zk-SNARK redesigned.** `zkSNARK/zk_encoder_decoder.py` now uses a field-native node
  encoding: every 32-byte word is < p, and a leaf commits to its full key. The new
  `circuit_directory/mpt_batch_16.circom` binds root, key and value as public inputs, and
  constrains the node type tags, batch counts and the nibble range. The verifier rebuilds the public
  inputs from its own (root, keys, values) and checks the proof in a persistent snarkjs process.
  264,432 constraints; the setup uses `powersOfTau28_hez_final_19.ptau`.
  The old circuit did not bind the key, and it bound the value only modulo p.
* **Old random-data Verkle removed.** `verkle_eip6800` on mainnet data is the only Verkle backend.
* `scripts/soundness_checks.py`: negative tests (tampered value, key and root must be rejected) for every backend.
* `benchmark.py` interleaves repetitions across batch sizes (rep-major), warms caches with an untimed
  proof (16 accounts; 1 for the ZK backends), and samples the same accounts for every scheme.
* `zkstarkmerkle` proof size counts the binary receipt (4 bytes per u32 word of seals and claim digests,
  journal excluded). The JSON transport encoding is about 2.6x larger. On mainnet paths (8,192-account trie)
  one receipt takes about 5.5 min and 8.5 GB RAM on a 4-core laptop, so the paper grid for the STARK is
  batches 1-8 and tree sizes 256-8192 at batch 1.
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
├── benchmark.py                    # paper experiments: repetitions, paired samples -> results/paper_results.csv
├── *.json (root)                   # run configs + dataset (data.json: 8223 mainnet accounts)
├── results_latest.csv              # all benchmark results
├── tree_ids.txt                    # ids of generated trees (tree_storage/<id>)
│
├── tree/  prover/  verifier/  setups/   # implementations, auto-registered via registry/
├── registry/                       # TREE / PROVER / VERIFIER / SETUP registries
├── merkle/                         # MPT nodes, nibble paths, hashing (+ poseidon_worker.js)
├── verkle/                         # KZG commitments, serialization, field utils
├── zkSTARK/                        # Retired Python STARK implementation (not the active backend)
├── zkstark_risc0/                  # Active RISC Zero guest, host, bridge, Cargo.lock
├── tests/                          # STARK adapter and real-receipt tests
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
python3.11 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
# (requirements.txt is the original, minimal list)
```
`plyvel` needs the LevelDB headers (`sudo apt install libleveldb-dev`).

### 2. Node.js (Poseidon worker started by the tree module, SNARK verification)

```bash
npm ci                          # circomlibjs + snarkjs (used by merkle/poseidon_worker.js)
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
circom circuit_directory/mpt_batch_16.circom --O2 --r1cs --c --sym -o circuit_directory/build16
make -C circuit_directory/build16/mpt_batch_16_cpp
cp -r circuit_directory/build16/mpt_batch_16_cpp circuit_directory/mpt_batch_16_cpp

# trusted setup: 264,432 constraints -> Hermez powers-of-tau with 2^19
snarkjs groth16 setup circuit_directory/build16/mpt_batch_16.r1cs powersOfTau28_hez_final_19.ptau mpt_batch_16_0000.zkey
snarkjs zkey contribute mpt_batch_16_0000.zkey mpt_batch_16.zkey --name="phase2" -e="<random>"
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
All trees read accounts from `data.json` (`verkle_eip6800` stores two EIP-6800 leaves per account).

### Prove + verify once

Edit `proving_setup.json` (`TREE_ID`, `PROVER_TYPE`, `VERIFIER_TYPE`, `NUM_KEYS_TO_PROVE`, …), then:

```bash
python prove_verify.py
```

### Paper experiments

```bash
python benchmark.py experiments/paper_config.json        # resumable; skips rows already verified
python benchmark.py experiments/paper_config.json --only batch
python experiments/paper_plots.py                        # figures + summary table -> results/figures/
python scripts/soundness_checks.py                       # negative tests -> results/soundness_checks.json
```

### Legacy sweeps (thesis)

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
