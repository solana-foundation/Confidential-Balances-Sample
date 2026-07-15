//! Account scaffolding shared by the examples: load a keypair from the
//! environment, create a confidential-transfer mint, and create + configure a
//! token account for confidential transfers.

use crate::configure::{
    configure_account_for_confidential_transfers, configure_account_with_extensions,
};
use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use solana_zk_sdk::encryption::elgamal::ElGamalKeypair;
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalPubkey;
use spl_associated_token_account::instruction::create_associated_token_account;
use spl_token_2022::{
    extension::{
        confidential_transfer::instruction::initialize_mint,
        confidential_transfer_fee::instruction::initialize_confidential_transfer_fee_config,
        transfer_fee::instruction::initialize_transfer_fee_config, ExtensionType,
    },
    instruction::{
        initialize_mint as initialize_mint_base, initialize_permanent_delegate,
    },
    state::Mint,
};

/// Load a 64-byte JSON keypair array (solana-keygen format) from env var `var`.
pub fn load_keypair_env(var: &str) -> CtResult<Keypair> {
    let json = std::env::var(var).map_err(|_| format!("{var} environment variable not set"))?;
    let bytes: Vec<u8> = serde_json::from_str(&json).map_err(|e| format!("parse {var}: {e}"))?;
    if bytes.len() != 64 {
        return Err(format!("invalid {var}: expected 64 bytes, got {}", bytes.len()).into());
    }
    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&bytes[0..32]);
    Ok(Keypair::new_from_array(secret_key))
}

/// Create a Token-2022 mint with the confidential-transfer extension:
/// auto-approve new accounts, and a freshly generated auditor ElGamal key.
pub fn create_confidential_mint(
    client: &RpcClient,
    payer: &dyn Signer,
    decimals: u8,
) -> CtResult<Keypair> {
    let mint = Keypair::new();
    let space =
        ExtensionType::try_calculate_account_len::<Mint>(&[ExtensionType::ConfidentialTransferMint])?;
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
        decimals,
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

/// Create a Token-2022 mint with confidential transfers, confidential
/// transfer fees, and a permanent delegate:
///
/// * `TransferFeeConfig` — every transfer withholds `fee_basis_points` of the
///   amount, capped at `maximum_fee`, on the recipient account.
/// * `ConfidentialTransferFeeConfig` — the withheld amount on a confidential
///   transfer is encrypted under `withheld_authority_elgamal_pubkey`, so only
///   that key's holder can decrypt (and later withdraw) accumulated fees.
/// * `PermanentDelegate` — `permanent_delegate` can transfer or burn from any
///   token account of this mint, no owner signature needed.
///
/// `payer` is the mint authority, fee-config authority, and withdraw-withheld
/// authority.
pub fn create_confidential_fee_mint(
    client: &RpcClient,
    payer: &dyn Signer,
    decimals: u8,
    fee_basis_points: u16,
    maximum_fee: u64,
    withheld_authority_elgamal_pubkey: &PodElGamalPubkey,
    permanent_delegate: &Pubkey,
) -> CtResult<Keypair> {
    let mint = Keypair::new();
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialTransferFeeConfig,
        ExtensionType::TransferFeeConfig,
        ExtensionType::PermanentDelegate,
    ])?;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let auditor_elgamal = ElGamalKeypair::new_rand();
    let auditor_pubkey_pod: PodElGamalPubkey = (*auditor_elgamal.pubkey()).into();
    let payer_pubkey = payer.pubkey();

    let create_account_ix = system_instruction::create_account(
        &payer_pubkey,
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
    let init_ct_fee_ix = initialize_confidential_transfer_fee_config(
        &spl_token_2022::id(),
        &mint.pubkey(),
        Some(payer_pubkey),
        withheld_authority_elgamal_pubkey,
    )?;
    let init_fee_ix = initialize_transfer_fee_config(
        &spl_token_2022::id(),
        &mint.pubkey(),
        Some(&payer_pubkey),
        Some(&payer_pubkey),
        fee_basis_points,
        maximum_fee,
    )?;
    let init_delegate_ix = initialize_permanent_delegate(
        &spl_token_2022::id(),
        &mint.pubkey(),
        permanent_delegate,
    )?;
    let init_mint_ix = initialize_mint_base(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &payer.pubkey(),
        None,
        decimals,
    )?;

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[
            create_account_ix,
            init_ct_ix,
            init_ct_fee_ix,
            init_fee_ix,
            init_delegate_ix,
            init_mint_ix,
        ],
        Some(&payer.pubkey()),
        &[payer, &mint],
        blockhash,
    );
    client.send_and_confirm_transaction(&tx)?;
    Ok(mint)
}

/// Create `owner`'s associated token account for `mint` and configure it for
/// confidential transfers.
pub async fn create_and_configure_account(
    client: &RpcClient,
    payer: &dyn Signer,
    owner: &Keypair,
    mint: &Pubkey,
) -> CtResult<()> {
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

    configure_account_for_confidential_transfers(client, payer, owner, mint).await?;
    Ok(())
}

/// Like [`create_and_configure_account`], but for a mint with confidential
/// fees: the token account also gets the `ConfidentialTransferFeeAmount`
/// extension that accumulates withheld fees.
pub async fn create_and_configure_fee_account(
    client: &RpcClient,
    payer: &dyn Signer,
    owner: &Keypair,
    mint: &Pubkey,
) -> CtResult<()> {
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

    configure_account_with_extensions(
        client,
        payer,
        owner,
        mint,
        &[ExtensionType::ConfidentialTransferFeeAmount],
    )
    .await?;
    Ok(())
}
