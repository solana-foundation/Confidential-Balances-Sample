//! Confidential transfer between accounts.
//!
//! Generates the three transfer proofs (equality, ciphertext-validity, range)
//! and submits them inline with the transfer in one v1 transaction via
//! `ProofLocation::InstructionOffset`. The whole flow is ~2.5 KB of the
//! 4096-byte v1 limit.

use crate::send::{send_v1_tx, CU_LIMIT_TRANSFER};
use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
};
use solana_zk_sdk_pod::encryption::{auth_encryption::PodAeCiphertext, elgamal::PodElGamalPubkey};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::transfer, ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use std::num::NonZeroI8;

#[allow(clippy::too_many_arguments)]
pub async fn transfer_confidential(
    client: &RpcClient,
    payer: &dyn Signer,
    sender: &Keypair,
    mint: &Pubkey,
    recipient: &Pubkey,
    amount: u64,
) -> MultiSigResult {
    transfer_confidential_with_progress(client, payer, sender, mint, recipient, amount, None).await
}

#[allow(clippy::too_many_arguments)]
pub async fn transfer_confidential_with_progress(
    client: &RpcClient,
    payer: &dyn Signer,
    sender: &Keypair,
    mint: &Pubkey,
    recipient: &Pubkey,
    amount: u64,
    progress: ProgressSink<'_>,
) -> MultiSigResult {
    let phase = |name: &str, detail: &str| {
        emit(
            progress,
            TransferProgress::Phase {
                name: name.to_string(),
                detail: detail.to_string(),
            },
        );
    };
    let sig_event = |label: &str, sig: &Signature| {
        emit(
            progress,
            TransferProgress::Signature {
                label: label.to_string(),
                sig: sig.to_string(),
            },
        );
    };

    phase("fetch-state", "Reading recipient and auditor pubkeys from chain");

    let sender_token_account = get_associated_token_address_with_program_id(
        &sender.pubkey(),
        mint,
        &spl_token_2022::id(),
    );
    let recipient_token_account =
        get_associated_token_address_with_program_id(recipient, mint, &spl_token_2022::id());

    // ----- Recipient ElGamal pubkey -----
    let recipient_acc_data = client.get_account(&recipient_token_account)?;
    let recipient_acc = StateWithExtensions::<TokenAccount>::unpack(&recipient_acc_data.data)?;
    let recipient_ext = recipient_acc.get_extension::<ConfidentialTransferAccount>()?;
    let recipient_elgamal_pubkey: ElGamalPubkey = recipient_ext
        .elgamal_pubkey
        .try_into()
        .map_err(|e| format!("recipient ElGamal pubkey: {e:?}"))?;

    // ----- Auditor ElGamal pubkey (optional) -----
    let mint_acc_data = client.get_account(mint)?;
    let mint_acc = StateWithExtensions::<Mint>::unpack(&mint_acc_data.data)?;
    let mint_ext = mint_acc.get_extension::<ConfidentialTransferMint>()?;
    let auditor_elgamal_pubkey: Option<ElGamalPubkey> =
        Option::<PodElGamalPubkey>::from(mint_ext.auditor_elgamal_pubkey)
            .map(|pod| {
                ElGamalPubkey::try_from(pod).map_err(|e| format!("auditor ElGamal pubkey: {e:?}"))
            })
            .transpose()?;

    phase(
        "derive-keys",
        "Deriving sender's ElGamal and AES keys from authority signature",
    );
    // *_legacy keeps the pre-zk-sdk-7 derivation; existing accounts depend on it.
    #[allow(deprecated)]
    let sender_elgamal =
        ElGamalKeypair::new_from_signer_legacy(sender, &sender_token_account.to_bytes())
            .map_err(|e| format!("derive sender ElGamal: {e}"))?;
    #[allow(deprecated)]
    let sender_aes = AeKey::new_from_signer_legacy(sender, &sender_token_account.to_bytes())
        .map_err(|e| format!("derive sender AES: {e}"))?;

    // ----- Sender state: available balance + decryptable available balance -----
    let sender_acc_data = client.get_account(&sender_token_account)?;
    let sender_acc = StateWithExtensions::<TokenAccount>::unpack(&sender_acc_data.data)?;
    let sender_ext = sender_acc.get_extension::<ConfidentialTransferAccount>()?;

    let current_available: ElGamalCiphertext = sender_ext
        .available_balance
        .try_into()
        .map_err(|e| format!("sender available balance: {e:?}"))?;
    let current_decryptable: AeCiphertext = sender_ext
        .decryptable_available_balance
        .try_into()
        .map_err(|e| format!("sender decryptable balance: {e:?}"))?;

    phase(
        "generate-proofs",
        "Generating equality, ciphertext-validity, and range proofs",
    );
    let proof_data = transfer_split_proof_data(
        &current_available,
        &current_decryptable,
        amount,
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
    )
    .map_err(|e| format!("transfer_split_proof_data: {e}"))?;

    // New decryptable available balance for the sender (post-transfer).
    let current_avail_plaintext = current_decryptable
        .decrypt(&sender_aes)
        .ok_or("decrypt current available")?;
    let new_avail_plaintext = current_avail_plaintext
        .checked_sub(amount)
        .ok_or("insufficient available balance")?;
    let new_decryptable: PodAeCiphertext = sender_aes.encrypt(new_avail_plaintext).into();

    let auditor_lo = proof_data
        .ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_lo;
    let auditor_hi = proof_data
        .ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_hi;

    // The `transfer` builder enforces offsets 1/2/3 and appends the three
    // VerifyProof instructions after the transfer instruction itself.
    let equality_loc = ProofLocation::InstructionOffset(
        NonZeroI8::new(1).unwrap(),
        &proof_data.equality_proof_data,
    );
    let validity_loc = ProofLocation::InstructionOffset(
        NonZeroI8::new(2).unwrap(),
        &proof_data
            .ciphertext_validity_proof_data_with_ciphertext
            .proof_data,
    );
    let range_loc = ProofLocation::InstructionOffset(
        NonZeroI8::new(3).unwrap(),
        &proof_data.range_proof_data,
    );

    let ixs = transfer(
        &spl_token_2022::id(),
        &sender_token_account,
        mint,
        &recipient_token_account,
        &new_decryptable,
        &auditor_lo,
        &auditor_hi,
        &sender.pubkey(),
        &[],
        equality_loc,
        validity_loc,
        range_loc,
    )?;

    phase(
        "submit-transfer",
        "Submitting one v1 transaction: transfer + 3 inline ZK proofs",
    );
    let sig = send_v1_tx(client, &ixs, &payer.pubkey(), &[payer, sender], CU_LIMIT_TRANSFER)?;
    sig_event("transfer+proofs", &sig);
    let signatures = vec![sig];

    emit(
        progress,
        TransferProgress::Done {
            sigs: signatures.iter().map(|s| s.to_string()).collect(),
        },
    );
    println!("✅ Confidential transfer complete: {sig}");
    Ok(signatures)
}
