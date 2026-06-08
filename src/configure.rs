//! Configure a token account for confidential transfers.
//!
//! Generates the PubkeyValidity proof with solana-zk-sdk 6.0.1, pre-verifies
//! it into a context state account, and references that account in
//! spl-token-2022 11.0.0's `configure_account` via
//! `ProofLocation::ContextStateAccount`.

use crate::types::*;
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;
use solana_zk_elgamal_proof_interface::{
    instruction::{ContextStateInfo, ProofInstruction},
    proof_data::PubkeyValidityProofContext,
    state::ProofContextState,
};
use solana_zk_sdk::{
    encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    zk_elgamal_proof_program::pubkey_validity::build_pubkey_validity_proof_data,
};
use solana_zk_sdk_pod::encryption::auth_encryption::PodAeCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::instruction::{configure_account, PubkeyValidityProofData},
        ExtensionType,
    },
    instruction::reallocate,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use std::mem::size_of;

const ZK_PROOF_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

pub async fn configure_account_for_confidential_transfers(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &Pubkey,
) -> SigResult {
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // 6.0.1-derived encryption keys.
    let elgamal_keypair = ElGamalKeypair::new_from_signer(authority, &token_account.to_bytes())
        .map_err(|e| format!("derive ElGamal keypair: {e}"))?;
    let aes_key = AeKey::new_from_signer(authority, &token_account.to_bytes())
        .map_err(|e| format!("derive AES key: {e}"))?;

    let max_pending_balance_credit_counter: u64 = 65536;

    let decryptable_balance: PodAeCiphertext = aes_key.encrypt(0u64).into();

    let proof_data = build_pubkey_validity_proof_data(&elgamal_keypair)
        .map_err(|e| format!("generate pubkey validity proof: {e}"))?;

    let proof_account = Keypair::new();
    let context_state_size = size_of::<ProofContextState<PubkeyValidityProofContext>>();
    let context_state_rent = client.get_minimum_balance_for_rent_exemption(context_state_size)?;

    let realloc_ix = reallocate(
        &spl_token_2022::id(),
        &token_account,
        &payer.pubkey(),
        &authority.pubkey(),
        &[&authority.pubkey()],
        &[ExtensionType::ConfidentialTransferAccount],
    )?;

    let create_proof_account_ix = system_instruction::create_account(
        &payer.pubkey(),
        &proof_account.pubkey(),
        context_state_rent,
        context_state_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );

    let proof_account_addr: Address = proof_account.pubkey().to_bytes().into();
    let authority_addr: Address = authority.pubkey().to_bytes().into();
    let verify_ix = ProofInstruction::VerifyPubkeyValidity.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &proof_account_addr,
            context_state_authority: &authority_addr,
        }),
        &proof_data,
    );

    let proof_location: ProofLocation<PubkeyValidityProofData> =
        ProofLocation::ContextStateAccount(&proof_account.pubkey());
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

    let mut instructions = vec![realloc_ix, create_proof_account_ix, verify_ix];
    instructions.extend(configure_ixs);

    let blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&payer.pubkey()),
        &[authority, payer, &proof_account],
        blockhash,
    );
    let signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "✅ Account configured for confidential transfers: {}",
        signature
    );
    Ok(signature)
}
