//! Example: Confidential transfer on a mint with transfer fees and a
//! permanent delegate.
//!
//! Demonstrates the three extensions working together:
//! * `TransferFeeConfig` + `ConfidentialTransferFeeConfig`: a 1% fee (capped)
//!   is withheld on the recipient account, encrypted under the withdraw-
//!   withheld authority's ElGamal key, then harvested to the mint.
//! * `PermanentDelegate`: the delegate burns tokens from the recipient's
//!   public balance without the recipient signing.
//!
//! Usage:
//! SOLANA_RPC_URL=https://api.devnet.solana.com PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example run_transfer_with_fees

use conf_balances_examples::balances::read_balances;
use conf_balances_examples::setup::{
    create_and_configure_fee_account, create_confidential_fee_mint, load_keypair_env,
};
use conf_balances_examples::{apply_pending, deposit, transfer_with_fee, withdraw};
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_keypair::Keypair;
use solana_native_token::LAMPORTS_PER_SOL;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer_fee::{
            instruction::harvest_withheld_tokens_to_mint, ConfidentialTransferFeeAmount,
            ConfidentialTransferFeeConfig,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::{Account as TokenAccount, Mint},
};
use std::env;

const DECIMALS: u8 = 9;
const FEE_BASIS_POINTS: u16 = 100; // 1%
const MAXIMUM_FEE: u64 = 1_000_000;
const TRANSFER_AMOUNT: u64 = 50_000_000;
const EXPECTED_FEE: u64 = 500_000; // 1% of 50_000_000, under the cap

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

    // The holder of this key can decrypt every withheld fee amount (and later
    // withdraw accumulated fees). The example keeps it to verify the fee.
    let withheld_authority_elgamal = ElGamalKeypair::new_rand();
    let withheld_authority_pod: PodElGamalPubkey = (*withheld_authority_elgamal.pubkey()).into();

    println!("\n🏭 Creating confidential mint with fees + permanent delegate...");
    println!("   Fee: {FEE_BASIS_POINTS} bps, max {MAXIMUM_FEE} base units");
    println!("   Permanent delegate: {} (payer)", payer.pubkey());
    let mint = create_confidential_fee_mint(
        &client,
        &payer,
        DECIMALS,
        FEE_BASIS_POINTS,
        MAXIMUM_FEE,
        &withheld_authority_pod,
        &payer.pubkey(),
    )?;
    println!("   Mint: {}", mint.pubkey());

    println!("\n🎫 Creating + configuring token accounts (with fee extension)...");
    create_and_configure_fee_account(&client, &payer, sender, &mint.pubkey()).await?;
    create_and_configure_fee_account(&client, &payer, &recipient, &mint.pubkey()).await?;

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

    println!("\n🪙 Minting tokens to sender...");
    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &sender_token_account,
        &payer.pubkey(),
        &[],
        1_000_000_000,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[mint_to_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    client.send_and_confirm_transaction(&tx)?;

    println!("\n💰 Depositing to confidential balance + applying pending...");
    deposit::deposit_to_confidential(&client, &payer, sender, &mint.pubkey(), 800_000_000, DECIMALS)
        .await?;
    apply_pending::apply_pending_balance(&client, &payer, sender, &mint.pubkey()).await?;
    display_balances(&client, "Sender (after deposit + apply)", sender, &mint.pubkey())?;

    println!("\n🔐 Executing confidential transfer with fee...");
    let signatures = transfer_with_fee::transfer_confidential_with_fee(
        &client,
        &payer,
        sender,
        &mint.pubkey(),
        &recipient.pubkey(),
        TRANSFER_AMOUNT,
    )
    .await?;

    display_balances(&client, "Sender (after transfer)", sender, &mint.pubkey())?;

    println!("\n🔄 Recipient applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, &recipient, &mint.pubkey()).await?;
    display_balances(&client, "Recipient (after apply)", &recipient, &mint.pubkey())?;
    println!(
        "\n   Recipient received {} net of the {} fee.",
        TRANSFER_AMOUNT - EXPECTED_FEE,
        EXPECTED_FEE
    );

    // ── Fee verification ──────────────────────────────────────────────────
    println!("\n💸 Verifying the withheld confidential fee...");

    // The withheld fee sits on the recipient account, encrypted under the
    // withdraw-withheld authority's ElGamal key.
    {
        let account_data = client.get_account(&recipient_token_account)?;
        let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
        let fee_ext = account.get_extension::<ConfidentialTransferFeeAmount>()?;
        let withheld: ElGamalCiphertext = fee_ext
            .withheld_amount
            .try_into()
            .map_err(|e| format!("decode withheld_amount: {e:?}"))?;
        let decrypted_fee = withheld
            .decrypt_u32(withheld_authority_elgamal.secret())
            .ok_or("decrypt withheld fee from recipient account")?;
        println!("   Withheld on recipient account: {decrypted_fee} base units");
        assert_eq!(decrypted_fee, EXPECTED_FEE);
        println!("   ✅ Matches expected fee ({FEE_BASIS_POINTS} bps of {TRANSFER_AMOUNT})");
    }

    // Harvesting moves withheld fees from token accounts onto the mint. It is
    // permissionless: anyone can crank it, since the amounts stay encrypted.
    println!("\n   Harvesting withheld fees to the mint...");
    let harvest_ix = harvest_withheld_tokens_to_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &[&recipient_token_account],
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[harvest_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let harvest_sig = client.send_and_confirm_transaction(&tx)?;
    println!("   Harvest tx: {harvest_sig}");

    {
        let mint_data = client.get_account(&mint.pubkey())?;
        let mint_account = StateWithExtensions::<Mint>::unpack(&mint_data.data)?;
        let ct_fee_config = mint_account.get_extension::<ConfidentialTransferFeeConfig>()?;
        let withheld: ElGamalCiphertext = ct_fee_config
            .withheld_amount
            .try_into()
            .map_err(|e| format!("decode mint withheld_amount: {e:?}"))?;
        let decrypted_fee = withheld
            .decrypt_u32(withheld_authority_elgamal.secret())
            .ok_or("decrypt withheld fee from mint")?;
        println!("   Withheld on mint after harvest: {decrypted_fee} base units");
        assert_eq!(decrypted_fee, EXPECTED_FEE);
        println!("   ✅ Fee successfully harvested to the mint");
    }

    // ── Permanent delegate ────────────────────────────────────────────────
    println!("\n🔑 Verifying the permanent delegate...");

    println!("   Recipient withdrawing 10,000,000 base units to public balance...");
    withdraw::withdraw_from_confidential(
        &client,
        &payer,
        &recipient,
        &mint.pubkey(),
        10_000_000,
        DECIMALS,
    )
    .await?;
    display_balances(&client, "Recipient (after withdraw)", &recipient, &mint.pubkey())?;

    // The permanent delegate (payer) burns from the recipient's public
    // balance. Only the delegate signs — the recipient does not.
    println!("\n   Permanent delegate burning 5,000,000 base units from recipient...");
    let burn_ix = spl_token_2022::instruction::burn_checked(
        &spl_token_2022::id(),
        &recipient_token_account,
        &mint.pubkey(),
        &payer.pubkey(),
        &[],
        5_000_000,
        DECIMALS,
    )?;
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[burn_ix],
        Some(&payer.pubkey()),
        &[&payer],
        blockhash,
    );
    let burn_sig = client.send_and_confirm_transaction(&tx)?;
    println!("   Burn tx: {burn_sig}");
    display_balances(&client, "Recipient (after delegate burn)", &recipient, &mint.pubkey())?;
    println!("   ✅ Delegate burned from the recipient's account without their signature");

    println!("\n📝 Transfer transaction signatures:");
    for (i, sig) in signatures.iter().enumerate() {
        println!("   {}. {}", i + 1, sig);
    }

    println!("\n📋 Account addresses:");
    println!("   Mint:                    {}", mint.pubkey());
    println!("   Sender token account:    {sender_token_account}");
    println!("   Recipient token account: {recipient_token_account}");

    Ok(())
}
