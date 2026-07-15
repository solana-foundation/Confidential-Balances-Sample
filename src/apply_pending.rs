//! Apply pending balance to available balance.
//!
//! Decrypts pending + available balances using `solana-zk-sdk = 6.0.1` keys,
//! re-encrypts the new available balance with AES, and submits the
//! `ApplyPendingBalance` instruction. The new AES ciphertext is byte-cast to
//! the legacy `PodAeCiphertext` type that `spl-token-2022 = 10.0.0` expects.

use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{signature::Signer, transaction::Transaction};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::ElGamalKeypair,
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext as PodElGamalCiphertextV6;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::apply_pending_balance as apply_pending_balance_instruction,
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    solana_zk_sdk::encryption::pod::auth_encryption::PodAeCiphertext as PodAeCiphertextLegacy,
    state::Account as TokenAccount,
};

pub async fn apply_pending_balance(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
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

    // Byte-cast the 4.0 pending-balance ciphertexts to 6.0.1 and decrypt with
    // the ElGamal key. Pending lo/hi are bounded, so decrypt_u32 is fine here.
    let pending_lo_v6: PodElGamalCiphertextV6 = PodElGamalCiphertextV6(
        bytemuck::bytes_of(&ct_extension.pending_balance_lo)
            .try_into()
            .map_err(|_| "pending_balance_lo size")?,
    );
    let pending_hi_v6: PodElGamalCiphertextV6 = PodElGamalCiphertextV6(
        bytemuck::bytes_of(&ct_extension.pending_balance_hi)
            .try_into()
            .map_err(|_| "pending_balance_hi size")?,
    );
    let pending_lo: solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        pending_lo_v6.try_into().map_err(|e| format!("{e:?}"))?;
    let pending_hi: solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        pending_hi_v6.try_into().map_err(|e| format!("{e:?}"))?;
    let pending_lo_amount = pending_lo
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_lo")? as u64;
    let pending_hi_amount = pending_hi
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_hi")? as u64;

    // Read the current available balance from the AES-encrypted decryptable
    // balance. ElGamal's decrypt_u32 only recovers values up to 2^32 raw units,
    // so it fails for realistic balances; the AES field has no such limit.
    let decryptable_bytes: [u8; 36] =
        bytemuck::bytes_of(&ct_extension.decryptable_available_balance)
            .try_into()
            .map_err(|_| "decryptable_available_balance size")?;
    let current_available = AeCiphertext::from_bytes(&decryptable_bytes)
        .ok_or("decode decryptable_available_balance")?
        .decrypt(&aes_key)
        .ok_or("decrypt available balance")?;

    let pending_total = pending_lo_amount + (pending_hi_amount << 16);
    let new_available = current_available + pending_total;

    // Encrypt new available with 6.0.1 AES, byte-cast to legacy PodAeCiphertext
    // for the spl-token-2022 instruction builder.
    let new_decryptable_v6 = aes_key.encrypt(new_available);
    let new_decryptable_legacy: PodAeCiphertextLegacy =
        PodAeCiphertextLegacy::from(new_decryptable_v6.to_bytes());

    let expected_counter: u64 = ct_extension.pending_balance_credit_counter.into();

    let apply_ix = apply_pending_balance_instruction(
        &spl_token_2022::id(),
        &token_account,
        expected_counter,
        &new_decryptable_legacy,
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
