//! Common test utilities and helpers

use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;
use spl_associated_token_account::{
    get_associated_token_address_with_program_id,
    instruction::create_associated_token_account,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::instruction::initialize_mint,
        ExtensionType,
    },
    instruction::initialize_mint as initialize_mint_base,
    solana_zk_sdk::encryption::elgamal::ElGamalKeypair,
    state::Mint,
};
use std::env;

/// Test environment configuration
pub struct TestEnv {
    pub client: RpcClient,
    pub payer: Keypair,
    pub is_local: bool,
}

impl TestEnv {
    /// Create a new test environment
    ///
    /// Checks SOLANA_RPC_URL environment variable:
    /// - If set to custom cluster (zk-edge.surfnet.dev), uses that
    /// - Otherwise uses local test validator (http://127.0.0.1:8899)
    pub fn new() -> Self {
        let rpc_url = env::var("SOLANA_RPC_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());

        let is_local = rpc_url.contains("127.0.0.1") || rpc_url.contains("localhost");

        println!("🔗 Connecting to: {}", rpc_url);
        println!("📍 Environment: {}", if is_local { "Local" } else { "Custom cluster" });

        let client = RpcClient::new_with_commitment(
            rpc_url,
            CommitmentConfig::confirmed(),
        );

        // Load payer from environment or generate new one
        let payer = if let Ok(keypair_json) = env::var("PAYER_KEYPAIR") {
            // Parse the JSON array into a byte array
            let bytes: Vec<u8> = serde_json::from_str(&keypair_json)
                .expect("Failed to parse PAYER_KEYPAIR as JSON array");

            // The keypair file is an array of 64 bytes: first 32 are secret key, last 32 are public key
            if bytes.len() != 64 {
                panic!("Invalid keypair: expected 64 bytes, got {}", bytes.len());
            }

            // Extract the first 32 bytes (secret key)
            let mut secret_key = [0u8; 32];
            secret_key.copy_from_slice(&bytes[0..32]);

            // Create keypair from secret key
            Keypair::new_from_array(secret_key)
        } else {
            // Generate new keypair for testing
            Keypair::new()
        };

        Self {
            client,
            payer,
            is_local,
        }
    }

    /// Request airdrop if on local test validator, or transfer from payer on custom cluster
    pub fn airdrop_if_needed(&self, pubkey: &solana_sdk::pubkey::Pubkey, lamports: u64) -> Result<(), Box<dyn std::error::Error>> {
        if !self.is_local {
            // Skip if trying to fund the payer itself (it's already funded)
            if pubkey == &self.payer.pubkey() {
                println!("⏭️  Skipping funding for payer (already funded)");
                return Ok(());
            }

            // On custom cluster, transfer SOL from payer to the target account
            println!("💸 Transferring {} SOL from payer to {}", lamports as f64 / LAMPORTS_PER_SOL as f64, pubkey);

            let transfer_ix = system_instruction::transfer(
                &self.payer.pubkey(),
                pubkey,
                lamports,
            );

            let recent_blockhash = self.client.get_latest_blockhash()?;
            let transaction = Transaction::new_signed_with_payer(
                &[transfer_ix],
                Some(&self.payer.pubkey()),
                &[&self.payer],
                recent_blockhash,
            );

            let signature = self.client.send_and_confirm_transaction(&transaction)?;
            println!("✅ Transfer confirmed: {}", signature);
            return Ok(());
        }

        println!("💰 Requesting airdrop of {} SOL", lamports as f64 / LAMPORTS_PER_SOL as f64);
        let signature = self.client.request_airdrop(pubkey, lamports)?;

        // Poll for balance update with retries
        let mut retries = 0;
        let max_retries = 10;
        loop {
            std::thread::sleep(std::time::Duration::from_millis(500));
            let balance_response = self.client.get_balance_with_commitment(
                pubkey,
                CommitmentConfig::confirmed()
            )?;
            let balance = balance_response.value;

            if balance >= lamports {
                println!("✅ Airdrop confirmed - New balance: {} SOL", balance as f64 / LAMPORTS_PER_SOL as f64);
                return Ok(());
            }

            retries += 1;
            if retries >= max_retries {
                return Err(format!(
                    "Airdrop timeout - expected at least {} lamports, got {} after {} retries. Signature: {}",
                    lamports, balance, max_retries, signature
                ).into());
            }
        }
    }

    /// Get payer's public key
    pub fn payer_pubkey(&self) -> solana_sdk::pubkey::Pubkey {
        self.payer.pubkey()
    }
}

/// Create a confidential transfer-enabled mint
pub fn create_confidential_mint(
    env: &TestEnv,
    authority: &Keypair,
    decimals: u8,
) -> Result<Keypair, Box<dyn std::error::Error>> {
    let mint = Keypair::new();

    println!("🏭 Creating confidential mint: {}", mint.pubkey());

    // Check payer balance
    let payer_balance = env.client.get_balance(&env.payer.pubkey())?;
    println!("💳 Payer balance: {} lamports", payer_balance);

    // Calculate space for mint with ConfidentialTransferMint extension
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint
    ])?;
    let rent = env.client.get_minimum_balance_for_rent_exemption(space)?;
    println!("💰 Space required: {} bytes, Rent: {} lamports", space, rent);

    // Generate auditor ElGamal keypair (optional - can be None)
    let auditor_elgamal = ElGamalKeypair::new_rand();

    // Create account instruction
    let create_account_ix = system_instruction::create_account(
        &env.payer.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    // Initialize confidential transfer extension
    // Convert ElGamalPubkey to PodElGamalPubkey
    let auditor_pubkey_pod: spl_token_2022::solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey =
        (*auditor_elgamal.pubkey()).into();

    let init_ct_ix = initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        None, // authority
        true, // auto_approve_new_accounts
        Some(auditor_pubkey_pod), // auditor_elgamal_pubkey as PodElGamalPubkey
    )?;

    // Initialize base mint
    let init_mint_ix = initialize_mint_base(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &authority.pubkey(),
        None, // freeze_authority
        decimals,
    )?;

    // Send transaction
    let recent_blockhash = env.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_account_ix, init_ct_ix, init_mint_ix],
        Some(&env.payer.pubkey()),
        &[&env.payer, &mint],
        recent_blockhash,
    );

    let signature = env.client.send_and_confirm_transaction(&transaction)?;
    println!("✅ Mint created: {}", signature);

    Ok(mint)
}

/// Create an associated token account
pub fn create_token_account(
    env: &TestEnv,
    mint: &solana_sdk::pubkey::Pubkey,
    owner: &solana_sdk::pubkey::Pubkey,
) -> Result<solana_sdk::pubkey::Pubkey, Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        owner,
        mint,
        &spl_token_2022::id(),
    );

    println!("🎫 Creating token account: {}", token_account);

    let create_ix = create_associated_token_account(
        &env.payer.pubkey(),
        owner,
        mint,
        &spl_token_2022::id(),
    );

    let recent_blockhash = env.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[create_ix],
        Some(&env.payer.pubkey()),
        &[&env.payer],
        recent_blockhash,
    );

    let signature = env.client.send_and_confirm_transaction(&transaction)?;
    println!("✅ Token account created: {}", signature);

    Ok(token_account)
}

/// Mint tokens to an account
pub fn mint_tokens(
    env: &TestEnv,
    mint: &solana_sdk::pubkey::Pubkey,
    destination: &solana_sdk::pubkey::Pubkey,
    authority: &Keypair,
    amount: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("🪙 Minting {} tokens to {}", amount, destination);

    let mint_to_ix = spl_token_2022::instruction::mint_to(
        &spl_token_2022::id(),
        mint,
        destination,
        &authority.pubkey(),
        &[],
        amount,
    )?;

    let recent_blockhash = env.client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[mint_to_ix],
        Some(&env.payer.pubkey()),
        &[&env.payer, authority],
        recent_blockhash,
    );

    let signature = env.client.send_and_confirm_transaction(&transaction)?;
    println!("✅ Minted tokens: {}", signature);

    Ok(())
}
