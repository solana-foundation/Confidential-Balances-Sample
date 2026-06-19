//! Shared scaffolding for the batch-transfer examples: spin up a confidential
//! mint, fund a sender's confidential available balance, and configure a set of
//! recipient accounts ready to receive. Both `batch_transfer_atomic` and
//! `batch_transfer_pipelined` examples build on this.

use conf_balances_examples::*;
use solana_client::rpc_client::RpcClient;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::{
    native_token::LAMPORTS_PER_SOL,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext as PodElGamalCiphertextV6;
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
        StateWithExtensions,
    },
    state::Account as TokenAccount,
};
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

/// Load the payer keypair from `PAYER_KEYPAIR` (a JSON byte array).
fn load_payer() -> Result<Keypair, Box<dyn Error>> {
    let keypair_json = env::var("PAYER_KEYPAIR")
        .map_err(|_| "PAYER_KEYPAIR environment variable not set")?;
    let bytes: Vec<u8> = serde_json::from_str(&keypair_json)?;
    if bytes.len() != 64 {
        return Err(format!("Invalid keypair: expected 64 bytes, got {}", bytes.len()).into());
    }
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&bytes[0..32]);
    Ok(Keypair::new_from_array(secret_key))
}

/// Create a confidential-transfer mint (auto-approve, random auditor key).
fn create_confidential_mint(client: &RpcClient, payer: &Keypair) -> Result<Keypair, Box<dyn Error>> {
    use solana_system_interface::instruction as system_instruction;
    use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey as PodElGamalPubkeyV6;
    use spl_token_2022::{
        extension::{confidential_transfer::instruction::initialize_mint, ExtensionType},
        instruction::initialize_mint as initialize_mint_base,
        solana_zk_sdk::encryption::pod::elgamal::PodElGamalPubkey as PodElGamalPubkeyLegacy,
        state::Mint,
    };

    let mint = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
    ])?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let auditor_elgamal = ElGamalKeypair::new_rand();
    let auditor_pod_v6: PodElGamalPubkeyV6 = (*auditor_elgamal.pubkey()).into();
    let auditor_pubkey_pod = PodElGamalPubkeyLegacy::from(auditor_pod_v6.0);

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
        DECIMALS,
    )?;

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[create_account_ix, init_ct_ix, init_mint_ix],
        Some(&payer.pubkey()),
        &[payer, &mint],
        blockhash,
    );
    client.send_and_confirm_transaction(&tx)?;
    Ok(mint)
}

/// Create a Token-2022 ATA for `owner` and configure it for confidential transfers.
async fn create_and_configure(
    client: &RpcClient,
    payer: &Keypair,
    owner: &Keypair,
    mint: &Pubkey,
) -> Result<(), Box<dyn Error>> {
    let create_ata_ix = create_associated_token_account(
        &payer.pubkey(),
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[create_ata_ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    client.send_and_confirm_transaction(&tx)?;

    configure::configure_account_for_confidential_transfers(client, payer, owner, mint).await?;
    Ok(())
}

/// Decrypt and pretty-print an account's confidential available balance.
pub fn print_available(
    client: &RpcClient,
    label: &str,
    owner: &Keypair,
    mint: &Pubkey,
) -> Result<(), Box<dyn Error>> {
    let token_account =
        get_associated_token_address_with_program_id(&owner.pubkey(), mint, &spl_token_2022::id());
    let elgamal_keypair = ElGamalKeypair::new_from_signer(owner, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(owner, &token_account.to_bytes())?;

    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ext = account.get_extension::<ConfidentialTransferAccount>()?;

    let available_v6: PodElGamalCiphertextV6 = PodElGamalCiphertextV6(
        bytemuck::bytes_of(&ext.available_balance)
            .try_into()
            .map_err(|_| "available_balance size")?,
    );
    let available_ct: ElGamalCiphertext = available_v6
        .try_into()
        .map_err(|e| format!("decode available_balance: {e:?}"))?;
    let available = available_ct
        .decrypt_u32(elgamal_keypair.secret())
        .unwrap_or(0);

    let avail_aes_bytes: [u8; 36] = bytemuck::bytes_of(&ext.decryptable_available_balance)
        .try_into()
        .map_err(|_| "decryptable size")?;
    let decryptable = AeCiphertext::from_bytes(&avail_aes_bytes)
        .and_then(|c| aes_key.decrypt(&c))
        .unwrap_or(0);

    println!(
        "   {label}: available(ElGamal)={available}, decryptable(AES)={decryptable}"
    );
    Ok(())
}

/// Stand up a mint, fund the sender's confidential available balance with
/// `funding` base units, and create `num_recipients` configured recipients.
pub async fn setup(num_recipients: usize, funding: u64) -> Result<Scenario, Box<dyn Error>> {
    let rpc_url =
        env::var("SOLANA_RPC_URL").unwrap_or_else(|_| "http://127.0.0.1:8899".to_string());
    println!("🔗 Connecting to: {rpc_url}");
    let client = RpcClient::new_with_commitment(rpc_url, CommitmentConfig::confirmed());

    let payer = load_payer()?;
    let sender = Keypair::new();
    println!("💰 Payer:  {}", payer.pubkey());
    println!(
        "💳 Balance: {} SOL",
        client.get_balance(&payer.pubkey())? as f64 / LAMPORTS_PER_SOL as f64
    );
    println!("📤 Sender: {}", sender.pubkey());

    println!("\n🏭 Creating confidential mint...");
    let mint = create_confidential_mint(&client, &payer)?;
    println!("   Mint: {}", mint.pubkey());

    println!("\n🎫 Configuring sender...");
    create_and_configure(&client, &payer, &sender, &mint.pubkey()).await?;

    let sender_token_account = get_associated_token_address_with_program_id(
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
        create_and_configure(&client, &payer, &recipient, &mint.pubkey()).await?;
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
