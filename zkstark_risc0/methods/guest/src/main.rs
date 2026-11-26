use mpt_zkstark_core::{verify_membership, Lookup};
use risc0_zkvm::guest::env;

fn main() {
    let lookup: Lookup = env::read();
    assert!(
        verify_membership(&lookup.root, &lookup.key, &lookup.value, &lookup.nodes),
        "invalid MPT membership witness"
    );
    env::commit(&lookup.statement());
}
