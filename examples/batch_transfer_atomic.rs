//! Example (option 1): batched confidential transfers from one sender, executed
//! atomically in a single v0 transaction.
//!
//! Every leg's proofs are pre-verified into context state accounts, an Address
//! Lookup Table compresses the account list, and one v0 transaction carries a
//! compute-budget bump plus all N `Transfer` instructions. In-order execution
//! within the transaction lets the offline-chained proofs validate against the
//! exact intermediate ciphertext each leg expects: all legs land, or none do.
//!
//! Bounded by transaction size and compute units. For very large fan-out, use
//! the pipelined example instead.
//!
//! Usage:
//! SOLANA_RPC_URL=https://api.devnet.solana.com \
//! PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
//! cargo run --example batch_transfer_atomic

mod common;

use conf_balances_examples::batch_transfer::{batch_transfer_atomic, TransferLeg};
use solana_signer::Signer;

/// CU ceiling for the atomic transaction. Each pre-verified `Transfer` does
/// ciphertext arithmetic (not full proof verification), so this leaves headroom
/// for a few legs; raise or lower with the batch size.
const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Three legs comfortably exceed a legacy transaction's 1232-byte limit once
    // every proof context account is referenced, which is exactly why this path
    // uses an Address Lookup Table + v0 transaction.
    let amounts: [u64; 3] = [120_000_000, 60_000_000, 30_000_000];
    let scenario = common::setup(amounts.len(), 1_000_000_000).await?;

    let legs: Vec<TransferLeg> = scenario
        .recipients
        .iter()
        .zip(amounts)
        .map(|(r, amount)| TransferLeg {
            recipient: r.pubkey(),
            amount,
        })
        .collect();

    println!("\n🔐 Atomic batch transfer ({} legs in one tx)...", legs.len());
    let sigs = batch_transfer_atomic(
        &scenario.client,
        &scenario.payer,
        &scenario.sender,
        &scenario.mint,
        &legs,
        COMPUTE_UNIT_LIMIT,
    )
    .await?;

    println!("\n📊 Final balances:");
    common::print_available(&scenario.client, "sender", &scenario.sender, &scenario.mint)?;

    println!("\n📝 {} transactions total (staging + 1 atomic transfer + cleanup)", sigs.len());
    Ok(())
}
