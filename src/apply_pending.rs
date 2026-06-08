//! Apply pending balance to available balance.
//!
//! Decrypts pending + available balances, re-encrypts the new available
//! balance with AES, and submits the `ApplyPendingBalance` instruction. Every
//! type is solana-zk-sdk 6.0.1, matching spl-token-2022 11.0.0's account
//! layout directly.

use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_signer::Signer;
use solana_transaction::Transaction;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
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

    // 6.0.1 key derivation.
    let elgamal_keypair = ElGamalKeypair::new_from_signer(authority, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(authority, &token_account.to_bytes())?;

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
    let available_balance: ElGamalCiphertext = ct_extension
        .available_balance
        .try_into()
        .map_err(|e| format!("available_balance: {e:?}"))?;

    let pending_lo_amount = pending_lo
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_lo")?;
    let pending_hi_amount = pending_hi
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_hi")?;
    let current_available = available_balance
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt available_balance")?;

    let pending_total = pending_lo_amount + (pending_hi_amount << 16);
    let new_available = current_available + pending_total;

    let new_decryptable: PodAeCiphertext = aes_key.encrypt(new_available as u64).into();

    let expected_counter: u64 = ct_extension.pending_balance_credit_counter.into();

    let apply_ix = apply_pending_balance_instruction(
        &spl_token_2022::id(),
        &token_account,
        expected_counter,
        &new_decryptable,
        &authority.pubkey(),
        &[&authority.pubkey()],
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[apply_ix],
        Some(&payer.pubkey()),
        &[payer, authority],
        recent_blockhash,
    );

    let signature = client.send_and_confirm_transaction(&transaction)?;
    println!(
        "✅ Applied pending balance. New available: {} tokens. Tx: {}",
        new_available, signature
    );
    Ok(signature)
}
