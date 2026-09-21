//! Configure a token account for confidential transfers.
//!
//! Generates the PubkeyValidity proof and submits it inline with the
//! `configure_account` instruction in one v1 transaction via
//! `ProofLocation::InstructionOffset`.

use crate::send::{send_v1_tx, CU_LIMIT_CONFIGURE};
use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_zk_sdk::{
    encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use solana_zk_sdk_pod::encryption::auth_encryption::PodAeCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{confidential_transfer::instruction::configure_account, ExtensionType},
    instruction::reallocate,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use std::num::NonZeroI8;

pub async fn configure_account_for_confidential_transfers(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &Pubkey,
) -> SigResult {
    configure_account_with_extensions(client, payer, authority, mint, &[]).await
}

/// Like [`configure_account_for_confidential_transfers`], but reallocates the
/// token account for `extra_extensions` too. A mint with confidential fees
/// needs its accounts to carry `ExtensionType::ConfidentialTransferFeeAmount`.
pub async fn configure_account_with_extensions(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &Pubkey,
    extra_extensions: &[ExtensionType],
) -> SigResult {
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // *_legacy keeps the pre-zk-sdk-7 derivation; existing accounts depend on it.
    #[allow(deprecated)]
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer_legacy(authority, &token_account.to_bytes())
            .map_err(|e| format!("derive ElGamal keypair: {e}"))?;
    #[allow(deprecated)]
    let aes_key = AeKey::new_from_signer_legacy(authority, &token_account.to_bytes())
        .map_err(|e| format!("derive AES key: {e}"))?;

    let max_pending_balance_credit_counter: u64 = 65536;

    let decryptable_balance: PodAeCiphertext = aes_key.encrypt(0u64).into();

    let proof_data = build_pubkey_validity_proof_data(&elgamal_keypair)
        .map_err(|e| format!("generate pubkey validity proof: {e}"))?;

    let mut extensions = vec![ExtensionType::ConfidentialTransferAccount];
    extensions.extend_from_slice(extra_extensions);
    let realloc_ix = reallocate(
        &spl_token_2022::id(),
        &token_account,
        &payer.pubkey(),
        &authority.pubkey(),
        &[&authority.pubkey()],
        &extensions,
    )?;

    // Offset 1: the builder appends the VerifyPubkeyValidity instruction
    // directly after `configure_account`; realloc precedes both.
    let proof_location = ProofLocation::InstructionOffset(NonZeroI8::new(1).unwrap(), &proof_data);
    let configure_ixs = configure_account(
        &spl_token_2022::id(),
        &token_account,
        mint,
        &decryptable_balance,
        max_pending_balance_credit_counter,
        &authority.pubkey(),
        &[],
        proof_location,
    )?;

    let mut instructions = vec![realloc_ix];
    instructions.extend(configure_ixs);

    let signature = send_v1_tx(
        client,
        &instructions,
        &payer.pubkey(),
        &[payer, authority],
        CU_LIMIT_CONFIGURE,
    )?;

    println!(
        "✅ Account configured for confidential transfers: {}",
        signature
    );
    Ok(signature)
}
