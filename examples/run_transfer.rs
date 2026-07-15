//! Example: Run a confidential transfer on devnet (or any cluster whose
//! deployed ZK ElGamal Proof program matches solana-zk-sdk = 6.0.1).
//!
//! Usage:
//! SOLANA_RPC_URL=https://api.devnet.solana.com PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example run_transfer

use conf_balances_examples::balances::read_balances;
use conf_balances_examples::setup::{
    create_and_configure_account, create_confidential_mint, load_keypair_env,
};
use conf_balances_examples::{apply_pending, deposit, transfer};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_native_token::LAMPORTS_PER_SOL;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use std::env;

const DECIMALS: u8 = 9;

/// Decrypt and display public / pending / available balances for an account.
fn display_balances(
    client: &RpcClient,
    account_name: &str,
    owner: &Keypair,
    mint: &Pubkey,
) -> Result<(), Box<dyn std::error::Error>> {
    let b = read_balances(client, owner, mint)?;
    let divisor = 10_u64.pow(DECIMALS as u32) as f64;
    println!("\n📊 {account_name} Balance:");
    println!("   Public:    {:>12.9} tokens", b.public as f64 / divisor);
    println!("   Pending:   {:>12.9} tokens", b.pending as f64 / divisor);
    println!("   Available: {:>12.9} tokens", b.available as f64 / divisor);
    println!("   ─────────────────────────────");
    println!("   Total:     {:>12.9} tokens", b.total() as f64 / divisor);
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    println!("🔗 Connecting to: {rpc_url}");
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let payer = load_keypair_env("PAYER_KEYPAIR")?;
    println!("💰 Payer: {}", payer.pubkey());
    println!(
        "💳 Balance: {} SOL",
        client.get_balance(&payer.pubkey())? as f64 / LAMPORTS_PER_SOL as f64
    );

    let sender = &payer;
    let recipient = Keypair::new();

    println!("\n📋 Setting up accounts...");
    println!("  Sender: {}", sender.pubkey());
    println!("  Recipient: {}", recipient.pubkey());

    println!("\n🏭 Creating confidential mint...");
    let mint = create_confidential_mint(&client, &payer, DECIMALS)?;
    println!("  Mint: {}", mint.pubkey());

    println!("\n🎫 Creating + configuring token accounts...");
    create_and_configure_account(&client, &payer, sender, &mint.pubkey()).await?;
    create_and_configure_account(&client, &payer, &recipient, &mint.pubkey()).await?;

    let sender_token_account = get_associated_token_address_with_program_id(
        &sender.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );
    let recipient_token_account = get_associated_token_address_with_program_id(
        &recipient.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );
    println!("  Sender token account: {sender_token_account}");
    println!("  Recipient token account: {recipient_token_account}");

    println!("\n🪙 Minting tokens to sender...");
    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
        &[],
        1_000_000_000,
    )?;
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[mint_to_ix],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    client.send_and_confirm_transaction(&transaction)?;

    display_balances(&client, "Sender (after mint)", sender, &mint.pubkey())?;
    display_balances(&client, "Recipient (initial)", &recipient, &mint.pubkey())?;

    println!("\n💰 Depositing to confidential balance...");
    deposit::deposit_to_confidential(&client, &payer, sender, &mint.pubkey(), 800_000_000, DECIMALS)
        .await?;
    display_balances(&client, "Sender (after deposit)", sender, &mint.pubkey())?;

    println!("\n🔄 Applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, sender, &mint.pubkey()).await?;
    display_balances(&client, "Sender (after apply)", sender, &mint.pubkey())?;

    println!("\n🔐 Executing confidential transfer...");
    println!("   This will create 3 transactions:");
    println!("   - proof account creations + validity proof verification");
    println!("   - range proof verification");
    println!("   - equality proof verification + transfer + proof account closures");

    let signatures = transfer::transfer_confidential(
        &client,
        &payer,
        sender,
        &mint.pubkey(),
        &recipient.pubkey(),
        50_000_000,
    )
    .await?;

    println!("\n✅ Confidential transfer complete!");
    display_balances(&client, "Sender (after transfer)", sender, &mint.pubkey())?;
    display_balances(
        &client,
        "Recipient (after transfer - before apply)",
        &recipient,
        &mint.pubkey(),
    )?;

    println!("\n🔄 Recipient applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, &recipient, &mint.pubkey()).await?;
    display_balances(&client, "Recipient (after apply)", &recipient, &mint.pubkey())?;

    println!("\n📝 Transaction signatures:");
    for (i, sig) in signatures.iter().enumerate() {
        println!("   {}. {}", i + 1, sig);
    }

    println!("\n📋 Account Addresses (for querying balances):");
    println!("   Mint:                    {}", mint.pubkey());
    println!("   Sender token account:    {sender_token_account}");
    println!("   Recipient token account: {recipient_token_account}");
    println!("\n💡 Query balances with:");
    println!(
        "   MINT_ADDRESS={} OWNER_KEYPAIR=</path/to/owner/keypair.json> cargo run --example get_balances",
        mint.pubkey()
    );

    Ok(())
}
