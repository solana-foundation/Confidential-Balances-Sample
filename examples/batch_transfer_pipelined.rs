//! Example (option 2): batched confidential transfers from one sender, shipped
//! as a pipeline of confirmed transactions.
//!
//! All proofs are generated offline up front against the chained sender state,
//! then each leg is staged, transferred, and closed in order. No transaction
//! size or compute ceiling, so the fan-out is unbounded; the cost is one round
//! of confirmation per leg.
//!
//! Usage:
//! SOLANA_RPC_URL=https://api.devnet.solana.com \
//! PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
//! cargo run --example batch_transfer_pipelined

mod common;

use conf_balances_examples::batch_transfer::{batch_transfer_pipelined, TransferLeg};
use solana_sdk::signature::Signer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Fund with 1 token (1e9 base units); send 4 legs of varying size.
    let amounts: [u64; 4] = [100_000_000, 50_000_000, 25_000_000, 10_000_000];
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

    println!("\n🔐 Pipelined batch transfer ({} legs)...", legs.len());
    let sigs = batch_transfer_pipelined(
        &scenario.client,
        &scenario.payer,
        &scenario.sender,
        &scenario.mint,
        &legs,
    )
    .await?;

    println!("\n📊 Final balances:");
    common::print_available(&scenario.client, "sender", &scenario.sender, &scenario.mint)?;

    println!("\n📝 {} transactions total", sigs.len());
    Ok(())
}
