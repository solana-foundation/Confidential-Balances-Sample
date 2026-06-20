//! Example: Get and display encrypted confidential balances
//!
//! This example shows how to decrypt and display all balance types
//! (public, pending, available) for a confidential token account.
//!
//! Usage (command line args):
//! cargo run --example get_balances -- <MINT_ADDRESS> <OWNER_KEYPAIR_PATH>
//!
//! Usage (environment variables):
//! MINT_ADDRESS=<mint> OWNER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example get_balances

use conf_balances_examples::balances::{read_available_elgamal, read_balances, Balances};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::{read_keypair_file, Keypair};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::env;

/// Display balances in a formatted way.
fn display_balances(balances: &Balances, decimals: u8) {
    let divisor = 10_u64.pow(decimals as u32) as f64;
    println!("\n╔══════════════════════════════════════════╗");
    println!("║           BALANCE BREAKDOWN              ║");
    println!("╠══════════════════════════════════════════╣");
    println!("║                                          ║");
    println!("║  Public Balance:    {:>12.9} tokens  ║", balances.public as f64 / divisor);
    println!("║  Pending Balance:   {:>12.9} tokens  ║", balances.pending as f64 / divisor);
    println!("║  Available Balance: {:>12.9} tokens  ║", balances.available as f64 / divisor);
    println!("║  ──────────────────────────────────────  ║");
    println!("║  Total:             {:>12.9} tokens  ║", balances.total() as f64 / divisor);
    println!("║                                          ║");
    println!("╚══════════════════════════════════════════╝");

    println!("\n📝 Balance Types Explained:");
    println!("   • Public:    Visible to everyone on-chain");
    println!("   • Pending:   Encrypted balance from deposits/transfers (needs apply)");
    println!("   • Available: Encrypted balance ready to transfer or withdraw");
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    let mint_str = if args.len() >= 2 {
        args[1].clone()
    } else if let Ok(mint_env) = env::var("MINT_ADDRESS") {
        mint_env
    } else {
        eprintln!("Error: MINT_ADDRESS not provided");
        eprintln!("\nUsage (args):    {} <MINT_ADDRESS> <OWNER_KEYPAIR_PATH>", args[0]);
        eprintln!("Usage (env):     MINT_ADDRESS=<mint> OWNER_KEYPAIR=<json> {}", args[0]);
        std::process::exit(1);
    };
    let mint = mint_str
        .parse::<Pubkey>()
        .map_err(|_| format!("Invalid mint address: {mint_str}"))?;

    // Owner keypair from a file-path arg, or OWNER_KEYPAIR env as a JSON array.
    let owner = if args.len() >= 3 {
        read_keypair_file(&args[2])
            .map_err(|e| format!("Failed to read keypair from {}: {e}", args[2]))?
    } else if let Ok(keypair_json) = env::var("OWNER_KEYPAIR") {
        let bytes: Vec<u8> = serde_json::from_str(&keypair_json)
            .map_err(|e| format!("Failed to parse OWNER_KEYPAIR as JSON: {e}"))?;
        if bytes.len() != 64 {
            return Err(format!("Invalid keypair: expected 64 bytes, got {}", bytes.len()).into());
        }
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&bytes[0..32]);
        Keypair::new_from_array(secret_key)
    } else {
        eprintln!("Error: Owner keypair not provided (arg path or OWNER_KEYPAIR env)");
        std::process::exit(1);
    };

    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    println!("🔗 Connecting to: {rpc_url}");
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    println!("👤 Owner: {}", owner.pubkey());
    println!("🪙 Mint: {mint}\n", );

    let balances = read_balances(&client, &owner, &mint)?;

    // Cross-check the available balance via the (slower) ElGamal path.
    let available_elgamal = read_available_elgamal(&client, &owner, &mint)?;
    println!("🔓 Available balance decryption:");
    println!("   AES:     {} (fast path)", balances.available);
    println!("   ElGamal: {available_elgamal}");
    println!("   Match:   {}", balances.available == available_elgamal);

    display_balances(&balances, 9);

    println!("\n✅ Balance query complete!");
    Ok(())
}
