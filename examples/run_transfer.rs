//! Example: Run a confidential transfer on devnet (or any cluster whose
//! deployed ZK ElGamal Proof program matches solana-zk-sdk = 6.0.1).
//!
//! Usage:
//! SOLANA_RPC_URL=https://api.devnet.solana.com PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) cargo run --example run_transfer

use conf_balances_examples::*;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_native_token::LAMPORTS_PER_SOL;
use solana_keypair::Keypair;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
        StateWithExtensions,
    },
    state::Account as TokenAccount,
};
use std::env;

/// Display all balance types for a token account
fn display_balances(
    client: &RpcClient,
    account_name: &str,
    owner: &Keypair,
    mint: &solana_pubkey::Pubkey,
    decimals: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Derive encryption keys
    let elgamal_keypair = ElGamalKeypair::new_from_signer(
        owner,
        &token_account.to_bytes(),
    )?;
    let aes_key = AeKey::new_from_signer(
        owner,
        &token_account.to_bytes(),
    )?;

    // Fetch account data
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Public balance
    let public_balance = account.base.amount;

    let pending_lo: ElGamalCiphertext = ct_extension
        .pending_balance_lo
        .try_into()
        .map_err(|e| format!("decode pending_lo: {e:?}"))?;
    let pending_hi: ElGamalCiphertext = ct_extension
        .pending_balance_hi
        .try_into()
        .map_err(|e| format!("decode pending_hi: {e:?}"))?;

    let pending_lo_amount = pending_lo
        .decrypt_u32(elgamal_keypair.secret())
        .unwrap_or(0);
    let pending_hi_amount = pending_hi
        .decrypt_u32(elgamal_keypair.secret())
        .unwrap_or(0);
    let pending_total = pending_lo_amount + (pending_hi_amount << 16);

    // Decrypt available balance using AES (cheap relative to ElGamal DLP).
    let decryptable_balance: AeCiphertext = ct_extension
        .decryptable_available_balance
        .try_into()
        .map_err(|e| format!("decode AeCiphertext: {e:?}"))?;
    let available_balance = aes_key.decrypt(&decryptable_balance).unwrap_or(0);

    // Format amounts with decimals
    let divisor = 10_u64.pow(decimals as u32) as f64;
    let public_formatted = public_balance as f64 / divisor;
    let pending_formatted = pending_total as f64 / divisor;
    let available_formatted = available_balance as f64 / divisor;
    let total = (public_balance + pending_total + available_balance) as f64 / divisor;

    println!("\n📊 {} Balance:", account_name);
    println!("   Public:    {:>12.9} tokens", public_formatted);
    println!("   Pending:   {:>12.9} tokens", pending_formatted);
    println!("   Available: {:>12.9} tokens", available_formatted);
    println!("   ─────────────────────────────");
    println!("   Total:     {:>12.9} tokens", total);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get RPC URL
    let rpc_url = env::var("SOLANA_RPC_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

    println!("🔗 Connecting to: {}", rpc_url);

    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    // Load payer from environment
    let payer = if let Ok(keypair_json) = env::var("PAYER_KEYPAIR") {
        let bytes: Vec<u8> = serde_json::from_str(&keypair_json)?;
        if bytes.len() != 64 {
            return Err(format!("Invalid keypair: expected 64 bytes, got {}", bytes.len()).into());
        }
        let mut secret_key = [0u8; 32];
        secret_key.copy_from_slice(&bytes[0..32]);
        Keypair::new_from_array(secret_key)
    } else {
        return Err("PAYER_KEYPAIR environment variable not set".into());
    };

    println!("💰 Payer: {}", payer.pubkey());
    println!("💳 Balance: {} SOL", client.get_balance(&payer.pubkey())? as f64 / LAMPORTS_PER_SOL as f64);

    // Create user accounts
    let sender = &payer;
    let recipient = Keypair::new();

    println!("\n📋 Setting up accounts...");
    println!("  Sender: {}", sender.pubkey());
    println!("  Recipient: {}", recipient.pubkey());

    // Create confidential mint
    println!("\n🏭 Creating confidential mint...");
    let mint = {
        use solana_transaction::Transaction;
        use solana_system_interface::instruction as system_instruction;
        use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
        use spl_token_2022::{
            extension::{confidential_transfer::instruction::initialize_mint, ExtensionType},
            instruction::initialize_mint as initialize_mint_base,
            state::Mint,
        };

        let mint = Keypair::new();
        let space = ExtensionType::try_calculate_account_len::<Mint>(&[
            ExtensionType::ConfidentialTransferMint,
        ])?;
        let rent = client.get_minimum_balance_for_rent_exemption(space)?;

        let auditor_elgamal = ElGamalKeypair::new_rand();
        let auditor_pubkey_pod: PodElGamalPubkey = (*auditor_elgamal.pubkey()).into();

        let create_account_ix = system_instruction::create_account(
            &payer.pubkey(),
            &mint.pubkey(),
            rent,
            space as u64,
            &spl_token_2022::id(),
        );

        let init_ct_ix = initialize_mint(
            &spl_token_2022::id(),
            &mint.pubkey(),
            None,
            true,
            Some(auditor_pubkey_pod),
        )?;

        let init_mint_ix = initialize_mint_base(
            &spl_token_2022::id(),
            &mint.pubkey(),
            &payer.pubkey(),
            None,
            9,
        )?;

        let recent_blockhash = client.get_latest_blockhash()?;
        let transaction = Transaction::new_signed_with_payer(
            &[create_account_ix, init_ct_ix, init_mint_ix],
            Some(&payer.pubkey()),
            &[&payer, &mint],
            recent_blockhash,
        );

        client.send_and_confirm_transaction(&transaction)?;
        println!("  Mint: {}", mint.pubkey());
        mint
    };

    // Create token accounts
    println!("\n🎫 Creating token accounts...");
    use spl_associated_token_account::{get_associated_token_address_with_program_id, instruction::create_associated_token_account};

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

    let create_sender_ata = create_associated_token_account(
        &payer.pubkey(),
        &sender.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    let create_recipient_ata = create_associated_token_account(
        &payer.pubkey(),
        &recipient.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    use solana_transaction::Transaction;
    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_sender_ata, create_recipient_ata],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );
    client.send_and_confirm_transaction(&transaction)?;

    println!("  Sender token account: {}", sender_token_account);
    println!("  Recipient token account: {}", recipient_token_account);

    // Configure accounts
    println!("\n⚙️  Configuring accounts for confidential transfers...");
    configure::configure_account_for_confidential_transfers(&client, &payer, &sender, &mint.pubkey()).await?;
    configure::configure_account_for_confidential_transfers(&client, &payer, &recipient, &mint.pubkey()).await?;

    // Mint tokens
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

    // Show initial balances
    display_balances(&client, "Sender (after mint)", &sender, &mint.pubkey(), 9)?;
    display_balances(&client, "Recipient (initial)", &recipient, &mint.pubkey(), 9)?;

    // Deposit to confidential
    println!("\n💰 Depositing to confidential balance...");
    deposit::deposit_to_confidential(&client, &payer, &sender, &mint.pubkey(), 800_000_000, 9).await?;
    display_balances(&client, "Sender (after deposit)", &sender, &mint.pubkey(), 9)?;

    // Apply pending
    println!("\n🔄 Applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, &sender, &mint.pubkey()).await?;
    display_balances(&client, "Sender (after apply)", &sender, &mint.pubkey(), 9)?;

    // Transfer confidentially
    println!("\n🔐 Executing confidential transfer...");
    println!("   This will create 7 transactions:");
    println!("   - 3 proof context state account creations");
    println!("   - 1 confidential transfer");
    println!("   - 3 proof account closures");

    let signatures = transfer::transfer_confidential(
        &client,
        &payer,
        &sender,
        &mint.pubkey(),
        &recipient.pubkey(),
        50_000_000,
    ).await?;

    println!("\n✅ Confidential transfer complete!");

    // Show balances after transfer
    display_balances(&client, "Sender (after transfer)", &sender, &mint.pubkey(), 9)?;
    display_balances(&client, "Recipient (after transfer - before apply)", &recipient, &mint.pubkey(), 9)?;

    // Recipient applies pending balance
    println!("\n🔄 Recipient applying pending balance...");
    apply_pending::apply_pending_balance(&client, &payer, &recipient, &mint.pubkey()).await?;
    display_balances(&client, "Recipient (after apply)", &recipient, &mint.pubkey(), 9)?;

    println!("\n📝 Transaction signatures:");
    for (i, sig) in signatures.iter().enumerate() {
        println!("   {}. {}", i + 1, sig);
    }

    println!("\n🔗 View on explorer:");
    println!("   https://explorer.solana.com/tx/{}?cluster=custom&customUrl=https%3A%2F%2Fzk-edge.surfnet.dev%3A8899", signatures[3]);

    println!("\n📋 Account Addresses (for querying balances):");
    println!("   Mint:                   {}", mint.pubkey());
    println!("   Sender token account:   {}", sender_token_account);
    println!("   Recipient token account: {}", recipient_token_account);
    println!("\n💡 Query balances with:");
    println!("   MINT_ADDRESS={} OWNER_KEYPAIR=</path/to/owner/keypair.json> cargo run --example get_balances", mint.pubkey());

    Ok(())
}
