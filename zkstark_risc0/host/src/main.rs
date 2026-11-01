use anyhow::{bail, Context, Result};
use mpt_zkstark_core::{Lookup, Statement};
use mpt_zkstark_methods::{MPT_MEMBERSHIP_ELF, MPT_MEMBERSHIP_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, ProverOpts, Receipt};
use serde::Deserialize;
use serde_json::json;
use std::io::{self, Read};

#[derive(Deserialize)]
struct Request {
    action: String,
    root: String,
    key: String,
    value: String,
    #[serde(default)]
    nodes: Vec<String>,
    proof: Option<String>,
}

fn hex_bytes(s: &str) -> Result<Vec<u8>> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).context("invalid hexadecimal input")
}

fn run(request: Request) -> Result<serde_json::Value> {
    let root: [u8; 32] = hex_bytes(&request.root)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("root must be 32 bytes"))?;
    let statement = Statement {
        root,
        key: hex_bytes(&request.key)?,
        value: hex_bytes(&request.value)?,
    };
    match request.action.as_str() {
        "prove" => {
            if request.nodes.is_empty() {
                bail!("empty MPT witness");
            }
            let lookup = Lookup {
                root,
                key: statement.key.clone(),
                value: statement.value.clone(),
                nodes: request.nodes.iter().map(|n| hex_bytes(n)).collect::<Result<_>>()?,
            };
            let env = ExecutorEnv::builder().write(&lookup)?.build()?;
            let receipt = default_prover()
                .prove_with_opts(env, MPT_MEMBERSHIP_ELF, &ProverOpts::composite())?
                .receipt;
            check_receipt(&receipt, &statement)?;
            Ok(json!({"proof": hex::encode(serde_json::to_vec(&receipt)?)}))
        }
        "verify" => {
            let raw = hex_bytes(request.proof.as_deref().context("missing proof")?)?;
            let receipt: Receipt = serde_json::from_slice(&raw).context("malformed receipt")?;
            check_receipt(&receipt, &statement)?;
            Ok(json!({"valid": true}))
        }
        _ => bail!("unknown action"),
    }
}

fn check_receipt(receipt: &Receipt, expected: &Statement) -> Result<()> {
    if !matches!(&receipt.inner, InnerReceipt::Composite(_)) {
        bail!("only real composite ZK-STARK receipts are accepted");
    }
    receipt.verify(MPT_MEMBERSHIP_ID)?;
    let actual: Statement = receipt.journal.decode().context("invalid public journal")?;
    if &actual != expected {
        bail!("receipt proves a different root, key, or value");
    }
    Ok(())
}

fn main() {
    // No dev mode or fake receipts, even if the caller sets RISC0_DEV_MODE.
    std::env::set_var("RISC0_PROVER", "local");
    let mut input = String::new();
    let result = io::stdin()
        .read_to_string(&mut input)
        .map_err(anyhow::Error::from)
        .and_then(|_| serde_json::from_str::<Request>(&input).map_err(anyhow::Error::from))
        .and_then(run);
    match result {
        Ok(output) => println!("{output}"),
        Err(error) => {
            eprintln!("{error:#}");
            std::process::exit(1);
        }
    }
}
