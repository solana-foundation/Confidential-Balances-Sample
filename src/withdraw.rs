//! Withdraw tokens from confidential balance to public balance.
//!
//! Generates the equality + range proofs and submits them inline with the
//! withdraw instruction in one v1 transaction via
//! `ProofLocation::InstructionOffset`.

use crate::send::{send_v1_tx, CU_LIMIT_WITHDRAW};
use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::auth_encryption::PodAeCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{instruction::withdraw, ConfidentialTransferAccount},
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::Account as TokenAccount,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::withdraw::withdraw_proof_data;
use std::num::NonZeroI8;

pub async fn withdraw_from_confidential(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &Pubkey,
    amount: u64,
    decimals: u8,
) -> SigResult {
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // *_legacy keeps the pre-zk-sdk-7 derivation; existing accounts depend on it.
    #[allow(deprecated)]
    let elgamal_keypair =
        ElGamalKeypair::new_from_signer_legacy(authority, &token_account.to_bytes())?;
    #[allow(deprecated)]
    let aes_key = AeKey::new_from_signer_legacy(authority, &token_account.to_bytes())?;

    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    let available_balance: ElGamalCiphertext = ct_extension
        .available_balance
        .try_into()
        .map_err(|e| format!("decode available_balance: {e:?}"))?;

    let current_available = available_balance
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt available balance")? as u64;

    if current_available < amount {
        return Err(format!(
            "Insufficient confidential balance: have {}, need {}",
            current_available, amount
        )
        .into());
    }

    let proof_data = withdraw_proof_data(
        &available_balance,
        current_available,
        amount,
        &elgamal_keypair,
    )
    .map_err(|e| format!("withdraw_proof_data: {e}"))?;

    // New decryptable available balance after withdraw.
    let new_available = current_available - amount;
    let new_decryptable: PodAeCiphertext = aes_key.encrypt(new_available).into();

    // The `withdraw` builder enforces offsets 1/2 and appends both
    // VerifyProof instructions after the withdraw instruction itself.
    let equality_loc = ProofLocation::InstructionOffset(
        NonZeroI8::new(1).unwrap(),
        &proof_data.equality_proof_data,
    );
    let range_loc = ProofLocation::InstructionOffset(
        NonZeroI8::new(2).unwrap(),
        &proof_data.range_proof_data,
    );

    let withdraw_ixs = withdraw(
        &spl_token_2022::id(),
        &token_account,
        mint,
        amount,
        decimals,
        &new_decryptable,
        &authority.pubkey(),
        &[],
        equality_loc,
        range_loc,
    )?;

    let sig = send_v1_tx(
        client,
        &withdraw_ixs,
        &payer.pubkey(),
        &[payer, authority],
        CU_LIMIT_WITHDRAW,
    )?;

    println!(
        "✅ Withdrew {} tokens to public balance. Remaining confidential: {}",
        amount, new_available
    );
    Ok(sig)
}
