//! Shared scaffolding for the batch-transfer examples: spin up a confidential
//! mint, fund a sender's confidential available balance, and configure a set of
//! recipient accounts ready to receive. The heavy lifting lives in the library
//! (`setup`, `balances`, `deposit`, `apply_pending`); this just orchestrates it.

use conf_balances_examples::balances::read_balances;
use conf_balances_examples::setup::{
    create_and_configure_account, create_confidential_mint, load_keypair_env,
};
use conf_balances_examples::{apply_pending, deposit};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_native_token::LAMPORTS_PER_SOL;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use std::env;
use std::error::Error;

pub const DECIMALS: u8 = 9;

/// Everything an example needs after setup: a funded confidential sender and a
/// list of configured recipients.
pub struct Scenario {
    pub client: RpcClient,
    pub payer: Keypair,
    pub sender: Keypair,
    pub mint: Pubkey,
    pub recipients: Vec<Keypair>,
}

/// Decrypt and print an account's confidential available balance.
pub fn print_available(
    client: &RpcClient,
    label: &str,
    owner: &Keypair,
    mint: &Pubkey,
) -> Result<(), Box<dyn Error>> {
    let b = read_balances(client, owner, mint)?;
    println!("   {label}: available={}, pending={}, public={}", b.available, b.pending, b.public);
    Ok(())
}

/// Stand up a mint, fund the sender's confidential available balance with
/// `funding` base units, and create `num_recipients` configured recipients.
pub async fn setup(num_recipients: usize, funding: u64) -> Result<Scenario, Box<dyn Error>> {
    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    println!("🔗 Connecting to: {rpc_url}");
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let payer = load_keypair_env("PAYER_KEYPAIR")?;
    let sender = Keypair::new();
    println!("💰 Payer:  {}", payer.pubkey());
    println!(
        "💳 Balance: {} SOL",
        client.get_balance(&payer.pubkey())? as f64 / LAMPORTS_PER_SOL as f64
    );
    println!("📤 Sender: {}", sender.pubkey());

    println!("\n🏭 Creating confidential mint...");
    let mint = create_confidential_mint(&client, &payer, DECIMALS)?;
    println!("   Mint: {}", mint.pubkey());

    println!("\n🎫 Configuring sender...");
    create_and_configure_account(&client, &payer, &sender, &mint.pubkey()).await?;

    let sender_token_account = spl_associated_token_account::get_associated_token_address_with_program_id(
        &sender.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    println!("🪙 Minting {funding} base units to sender...");
    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
        &[],
        funding,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[mint_to_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    client.send_and_confirm_transaction(&tx)?;

    println!("💰 Depositing to confidential balance + applying pending...");
    deposit::deposit_to_confidential(&client, &payer, &sender, &mint.pubkey(), funding, DECIMALS)
        .await?;
    apply_pending::apply_pending_balance(&client, &payer, &sender, &mint.pubkey()).await?;
    print_available(&client, "sender", &sender, &mint.pubkey())?;

    println!("\n🎫 Configuring {num_recipients} recipients...");
    let mut recipients = Vec::with_capacity(num_recipients);
    for i in 0..num_recipients {
        let recipient = Keypair::new();
        create_and_configure_account(&client, &payer, &recipient, &mint.pubkey()).await?;
        println!("   recipient {}: {}", i + 1, recipient.pubkey());
        recipients.push(recipient);
    }

    Ok(Scenario {
        client,
        payer,
        sender,
        mint: mint.pubkey(),
        recipients,
    })
}
