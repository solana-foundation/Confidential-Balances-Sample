//! Apply pending balance to available balance.
//!
//! Decrypts pending + available balances, re-encrypts the new available
//! balance with AES, and submits the `ApplyPendingBalance` instruction.

use crate::send::{send_v1_tx, CU_LIMIT_DEFAULT};
use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::auth_encryption::PodAeCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::apply_pending_balance as apply_pending_balance_instruction,
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::Account as TokenAccount,
};

pub async fn apply_pending_balance(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &solana_pubkey::Pubkey,
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

    let pending_lo: ElGamalCiphertext = ct_extension
        .pending_balance_lo
        .try_into()
        .map_err(|e| format!("pending_balance_lo: {e:?}"))?;
    let pending_hi: ElGamalCiphertext = ct_extension
        .pending_balance_hi
        .try_into()
        .map_err(|e| format!("pending_balance_hi: {e:?}"))?;
    // Pending lo/hi are bounded (16-bit split), so decrypt_u32 is fine here.
    let pending_lo_amount = pending_lo
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_lo")? as u64;
    let pending_hi_amount = pending_hi
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_hi")? as u64;

    // Read the current available balance from the AES-encrypted decryptable
    // balance. ElGamal's decrypt_u32 only recovers values up to 2^32 raw
    // units, so it fails for realistic balances; the AES field has no limit.
    let current_decryptable: AeCiphertext = ct_extension
        .decryptable_available_balance
        .try_into()
        .map_err(|e| format!("decryptable_available_balance: {e:?}"))?;
    let current_available = current_decryptable
        .decrypt(&aes_key)
        .ok_or("decrypt decryptable_available_balance")?;

    let pending_total = pending_lo_amount + (pending_hi_amount << 16);
    let new_available = current_available
        .checked_add(pending_total)
        .ok_or("available + pending overflows u64")?;

    let new_decryptable: PodAeCiphertext = aes_key.encrypt(new_available).into();

    let expected_counter: u64 = ct_extension.pending_balance_credit_counter.into();

    let apply_ix = apply_pending_balance_instruction(
        &spl_token_2022::id(),
        &token_account,
        expected_counter,
        &new_decryptable,
        &authority.pubkey(),
        &[&authority.pubkey()],
    )?;

    let signature = send_v1_tx(
        client,
        &[apply_ix],
        &payer.pubkey(),
        &[payer, authority],
        CU_LIMIT_DEFAULT,
    )?;
    println!(
        "✅ Applied pending balance. New available: {} tokens. Tx: {}",
        new_available, signature
    );
    Ok(signature)
}
