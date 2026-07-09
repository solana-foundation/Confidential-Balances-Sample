//! Confidential transfer between accounts (bypass mode).
//!
//! Generates the three transfer proofs (equality, ciphertext-validity, range)
//! using `spl-token-confidential-transfer-proof-generation = 0.6.0`
//! (`solana-zk-sdk = 6.0.1`), pre-verifies each into a context state account,
//! then references those accounts in `spl-token-2022 = 10.0.0`'s transfer ix
//! via `ProofLocation::ContextStateAccount`. The 4.0 ↔ 6.0.1 boundary is
//! crossed by zero-copy byte casts of POD types.

use crate::types::*;
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer},
    transaction::Transaction,
};
use solana_system_interface::instruction as system_instruction;
use solana_zk_elgamal_proof_interface::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::{
        BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
        CiphertextCommitmentEqualityProofContext,
    },
    state::ProofContextState,
};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
};
use solana_zk_sdk_pod::encryption::elgamal::{
    PodElGamalCiphertext as PodElGamalCiphertextV6, PodElGamalPubkey as PodElGamalPubkeyV6,
};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::{
                inner_transfer, BatchedGroupedCiphertext3HandlesValidityProofData,
                BatchedRangeProofU128Data, CiphertextCommitmentEqualityProofData,
            },
            ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    solana_zk_sdk::encryption::pod::{
        auth_encryption::PodAeCiphertext as PodAeCiphertextLegacy,
        elgamal::{
            PodElGamalCiphertext as PodElGamalCiphertextLegacy,
            PodElGamalPubkey as PodElGamalPubkeyLegacy,
        },
    },
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use std::mem::size_of;

const ZK_PROOF_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

/// Byte offset of the proof data inside an spl-record account
/// (`RecordData::WRITABLE_START_INDEX`: 1-byte version + 32-byte authority).
const RECORD_PROOF_OFFSET: u32 = 33;

/// Per-tx write payloads for staging the proof into a record account, sized to
/// stay under the 1232-byte tx limit. The first write also carries
/// create_account + initialize, so it gets a smaller budget; the final write
/// also carries the context create + verify-from-account, which it has room for.
const RECORD_FIRST_CHUNK: usize = 750;
const RECORD_WRITE_CHUNK: usize = 900;

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

    // ----- Recipient ElGamal pubkey (legacy → 6.0.1 byte-cast) -----
    let recipient_acc_data = client.get_account(&recipient_token_account)?;
    let recipient_acc = StateWithExtensions::<TokenAccount>::unpack(&recipient_acc_data.data)?;
    let recipient_ext = recipient_acc.get_extension::<ConfidentialTransferAccount>()?;
    let recipient_elgamal_pubkey: ElGamalPubkey =
        cast_elgamal_pubkey_legacy_to_v6(&recipient_ext.elgamal_pubkey)?
            .try_into()
            .map_err(|e| format!("recipient ElGamal pubkey: {e:?}"))?;

    // ----- Auditor ElGamal pubkey (optional) -----
    let mint_acc_data = client.get_account(mint)?;
    let mint_acc = StateWithExtensions::<Mint>::unpack(&mint_acc_data.data)?;
    let mint_ext = mint_acc.get_extension::<ConfidentialTransferMint>()?;
    let auditor_elgamal_pubkey: Option<ElGamalPubkey> = {
        let pod_opt: Option<PodElGamalPubkeyLegacy> = mint_ext.auditor_elgamal_pubkey.into();
        pod_opt
            .map(|pod| -> CtResult<ElGamalPubkey> {
                let v6 = cast_elgamal_pubkey_legacy_to_v6(&pod)?;
                v6.try_into()
                    .map_err(|e| format!("auditor ElGamal pubkey: {e:?}").into())
            })
            .transpose()?
    };

    phase(
        "derive-keys",
        "Deriving sender's ElGamal and AES keys from authority signature",
    );
    let sender_elgamal = ElGamalKeypair::new_from_signer(sender, &sender_token_account.to_bytes())
        .map_err(|e| format!("derive sender ElGamal: {e}"))?;
    let sender_aes = AeKey::new_from_signer(sender, &sender_token_account.to_bytes())
        .map_err(|e| format!("derive sender AES: {e}"))?;

    // ----- Sender state: available balance + decryptable available balance -----
    let sender_acc_data = client.get_account(&sender_token_account)?;
    let sender_acc = StateWithExtensions::<TokenAccount>::unpack(&sender_acc_data.data)?;
    let sender_ext = sender_acc.get_extension::<ConfidentialTransferAccount>()?;

    let current_available_v6: ElGamalCiphertext =
        cast_elgamal_ciphertext_legacy_to_v6(&sender_ext.available_balance)?
            .try_into()
            .map_err(|e| format!("sender available balance: {e:?}"))?;
    let current_decryptable_v6: AeCiphertext =
        cast_ae_ciphertext_legacy_to_v6(&sender_ext.decryptable_available_balance)?;

    phase(
        "generate-proofs",
        "Generating equality, ciphertext-validity, and range proofs (zk-sdk 6.0.1)",
    );
    let proof_data = transfer_split_proof_data(
        &current_available_v6,
        &current_decryptable_v6,
        amount,
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
    )
    .map_err(|e| format!("transfer_split_proof_data: {e}"))?;

    phase(
        "create-proof-accounts",
        "Allocating + verifying 3 proof context state accounts (3 transactions)",
    );

    let mut signatures: Vec<Signature> = Vec::new();

    // 1. Equality proof
    let equality_account = Keypair::new();
    let equality_size = size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let equality_rent = client.get_minimum_balance_for_rent_exemption(equality_size)?;
    let equality_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &equality_account.pubkey(),
        equality_rent,
        equality_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );
    let equality_verify_ix = ProofInstruction::VerifyCiphertextCommitmentEquality
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &Address::from(equality_account.pubkey().to_bytes()),
                context_state_authority: &Address::from(sender.pubkey().to_bytes()),
            }),
            &proof_data.equality_proof_data,
        );
    // sender is the context-state authority but verify_proof records it as a
    // readonly non-signer; only payer (fee + create funder) and the new
    // proof account itself must sign.
    let sig = send_tx(
        client,
        &[equality_create_ix, equality_verify_ix],
        &[payer, &equality_account],
        &payer.pubkey(),
    )?;
    sig_event("equality-proof-account", &sig);
    signatures.push(sig);

    // 2. Ciphertext validity proof
    let validity_account = Keypair::new();
    let validity_size =
        size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>();
    let validity_rent = client.get_minimum_balance_for_rent_exemption(validity_size)?;
    let validity_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &validity_account.pubkey(),
        validity_rent,
        validity_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );
    let validity_verify_ix = ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &Address::from(validity_account.pubkey().to_bytes()),
                context_state_authority: &Address::from(sender.pubkey().to_bytes()),
            }),
            &proof_data
                .ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
        );
    let sig = send_tx(
        client,
        &[validity_create_ix, validity_verify_ix],
        &[payer, &validity_account],
        &payer.pubkey(),
    )?;
    sig_event("ciphertext-validity-proof-account", &sig);
    signatures.push(sig);

    // 3. Range proof — the inline U128 range proof (~1.4 KB) blows past the
    // 1232-byte tx limit even on its own, so it can't ride in a verify ix.
    // Stage it in an spl-record account, then verify *from* that account
    // (encode_verify_proof_from_account) so the verify ix carries only account
    // references. The context-account create + verify-from-account are appended
    // to the final record write so they don't cost an extra transaction.
    let record_account = Keypair::new();
    let range_account = Keypair::new();
    let range_size = size_of::<ProofContextState<BatchedRangeProofContext>>();
    let range_rent = client.get_minimum_balance_for_rent_exemption(range_size)?;
    let range_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &range_account.pubkey(),
        range_rent,
        range_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );
    let range_verify_ix = ProofInstruction::VerifyBatchedRangeProofU128
        .encode_verify_proof_from_account(
            Some(ContextStateInfo {
                context_state_account: &Address::from(range_account.pubkey().to_bytes()),
                context_state_authority: &Address::from(sender.pubkey().to_bytes()),
            }),
            &Address::from(record_account.pubkey().to_bytes()),
            RECORD_PROOF_OFFSET,
        );
    let mut record_sigs = stage_range_proof_record(
        client,
        payer,
        &record_account,
        bytemuck::bytes_of(&proof_data.range_proof_data),
        &[range_create_ix, range_verify_ix],
        &[&range_account],
    )?;
    for (i, sig) in record_sigs.iter().enumerate() {
        sig_event(&format!("range-proof-stage-{}", i + 1), sig);
    }
    signatures.append(&mut record_sigs);

    phase("submit-transfer", "Submitting confidential transfer and closing proof accounts");

    // New decryptable available balance for the sender (post-transfer).
    let current_avail_plaintext = current_decryptable_v6
        .decrypt(&sender_aes)
        .ok_or("decrypt current available")?;
    let new_avail_plaintext = current_avail_plaintext
        .checked_sub(amount)
        .ok_or("insufficient available balance")?;
    let new_decryptable_v6 = sender_aes.encrypt(new_avail_plaintext);
    let new_decryptable_legacy: PodAeCiphertextLegacy =
        cast_ae_ciphertext_v6_to_legacy(&new_decryptable_v6);

    let auditor_lo_v6 = proof_data
        .ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_lo;
    let auditor_hi_v6 = proof_data
        .ciphertext_validity_proof_data_with_ciphertext
        .ciphertext_hi;
    let auditor_lo_legacy: PodElGamalCiphertextLegacy =
        cast_elgamal_ciphertext_v6_to_legacy(&auditor_lo_v6);
    let auditor_hi_legacy: PodElGamalCiphertextLegacy =
        cast_elgamal_ciphertext_v6_to_legacy(&auditor_hi_v6);

    let equality_loc: ProofLocation<CiphertextCommitmentEqualityProofData> =
        ProofLocation::ContextStateAccount(&equality_account.pubkey());
    let validity_loc: ProofLocation<BatchedGroupedCiphertext3HandlesValidityProofData> =
        ProofLocation::ContextStateAccount(&validity_account.pubkey());
    let range_loc: ProofLocation<BatchedRangeProofU128Data> =
        ProofLocation::ContextStateAccount(&range_account.pubkey());

    let transfer_ix = inner_transfer(
        &spl_token_2022::id(),
        &sender_token_account,
        mint,
        &recipient_token_account,
        &new_decryptable_legacy,
        &auditor_lo_legacy,
        &auditor_hi_legacy,
        &sender.pubkey(),
        &[],
        equality_loc,
        validity_loc,
        range_loc,
    )?;

    // Close all three proof context accounts and the record account in the same
    // transaction as the transfer: the transfer consumes the verified proofs,
    // then the closes reclaim rent. Saves four standalone transactions.
    let payer_addr = Address::from(payer.pubkey().to_bytes());
    let sender_addr = Address::from(sender.pubkey().to_bytes());
    let close_ctx = |ctx: &Pubkey| {
        close_context_state(
            ContextStateInfo {
                context_state_account: &Address::from(ctx.to_bytes()),
                context_state_authority: &sender_addr,
            },
            &payer_addr,
        )
    };
    let ixs = [
        transfer_ix,
        close_ctx(&equality_account.pubkey()),
        close_ctx(&validity_account.pubkey()),
        close_ctx(&range_account.pubkey()),
        spl_record::instruction::close_account(
            &record_account.pubkey(),
            &payer.pubkey(),
            &payer.pubkey(),
        ),
    ];
    let sig = send_tx(client, &ixs, &[payer, sender], &payer.pubkey())?;
    sig_event("transfer-and-close", &sig);
    signatures.push(sig);

    emit(
        progress,
        TransferProgress::Done {
            sigs: signatures.iter().map(|s| s.to_string()).collect(),
        },
    );
    println!(
        "✅ Confidential transfer complete with {} transactions",
        signatures.len()
    );
    Ok(signatures)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

/// Create an spl-record account owned by `payer` (as record authority) and
/// write `proof_bytes` into it in tx-sized chunks. The first tx allocates +
/// initializes + writes the first chunk; subsequent chunks are write-only.
/// `trailing_ixs` (with `trailing_signers`) are appended to the final write tx
/// so the caller's create-context + verify-from-account ride along for free.
/// Returns one signature per transaction sent.
fn stage_range_proof_record(
    client: &RpcClient,
    payer: &dyn Signer,
    record_account: &Keypair,
    proof_bytes: &[u8],
    trailing_ixs: &[solana_sdk::instruction::Instruction],
    trailing_signers: &[&dyn Signer],
) -> CtResult<Vec<Signature>> {
    let space = proof_bytes.len() + RECORD_PROOF_OFFSET as usize;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    if proof_bytes.is_empty() {
        return Err("range proof had no bytes to stage".into());
    }

    // First chunk is smaller to leave room for create_account + initialize.
    let first_len = proof_bytes.len().min(RECORD_FIRST_CHUNK);
    let (first, rest) = proof_bytes.split_at(first_len);

    let mut sigs = Vec::new();
    let mut offset = 0usize;

    // tx 1: create + initialize + write the first chunk. We never append the
    // trailing ixs here (create_account + initialize already make this tx the
    // heaviest), so it can't overflow on a large single-chunk proof.
    sigs.push(send_tx(
        client,
        &[
            system_instruction::create_account(
                &payer.pubkey(),
                &record_account.pubkey(),
                rent,
                space as u64,
                &spl_record::id(),
            ),
            spl_record::instruction::initialize(&record_account.pubkey(), &payer.pubkey()),
            spl_record::instruction::write(&record_account.pubkey(), &payer.pubkey(), 0, first),
        ],
        &[payer, record_account],
        &payer.pubkey(),
    )?);
    offset += first.len();

    // Remaining chunks are write-only; the trailing ixs ride the last one.
    let mut chunks = rest.chunks(RECORD_WRITE_CHUNK).peekable();
    let mut trailing_attached = false;
    while let Some(chunk) = chunks.next() {
        let mut ixs = vec![spl_record::instruction::write(
            &record_account.pubkey(),
            &payer.pubkey(),
            offset as u64,
            chunk,
        )];
        let mut signers: Vec<&dyn Signer> = vec![payer];
        if chunks.peek().is_none() {
            ixs.extend_from_slice(trailing_ixs);
            signers.extend_from_slice(trailing_signers);
            trailing_attached = true;
        }
        sigs.push(send_tx(client, &ixs, &signers, &payer.pubkey())?);
        offset += chunk.len();
    }

    // Single-chunk proof: no write-only tx existed to carry the trailing ixs.
    if !trailing_attached {
        let mut signers: Vec<&dyn Signer> = vec![payer];
        signers.extend_from_slice(trailing_signers);
        sigs.push(send_tx(client, trailing_ixs, &signers, &payer.pubkey())?);
    }

    Ok(sigs)
}

/// Send a single tx, return the signature.
fn send_tx(
    client: &RpcClient,
    ixs: &[solana_sdk::instruction::Instruction],
    signers: &[&dyn Signer],
    payer: &Pubkey,
) -> CtResult<Signature> {
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(ixs, Some(payer), signers, blockhash);
    Ok(client.send_and_confirm_transaction(&tx)?)
}

// Byte-cast helpers across the 4.0 / 6.0.1 boundary. POD wire format is
// identical for these types; the Rust types are just version-tagged wrappers.

fn cast_elgamal_pubkey_legacy_to_v6(
    legacy: &PodElGamalPubkeyLegacy,
) -> CtResult<PodElGamalPubkeyV6> {
    let bytes: [u8; 32] = bytemuck::bytes_of(legacy)
        .try_into()
        .map_err(|_| "PodElGamalPubkey size")?;
    Ok(PodElGamalPubkeyV6(bytes))
}

fn cast_elgamal_ciphertext_legacy_to_v6(
    legacy: &PodElGamalCiphertextLegacy,
) -> CtResult<PodElGamalCiphertextV6> {
    let bytes: [u8; 64] = bytemuck::bytes_of(legacy)
        .try_into()
        .map_err(|_| "PodElGamalCiphertext size")?;
    Ok(PodElGamalCiphertextV6(bytes))
}

fn cast_elgamal_ciphertext_v6_to_legacy(
    v6: &PodElGamalCiphertextV6,
) -> PodElGamalCiphertextLegacy {
    PodElGamalCiphertextLegacy::from(v6.0)
}

fn cast_ae_ciphertext_legacy_to_v6(legacy: &PodAeCiphertextLegacy) -> CtResult<AeCiphertext> {
    let bytes: [u8; 36] = bytemuck::bytes_of(legacy)
        .try_into()
        .map_err(|_| "PodAeCiphertext size")?;
    AeCiphertext::from_bytes(&bytes).ok_or_else(|| "decode AeCiphertext bytes".into())
}

fn cast_ae_ciphertext_v6_to_legacy(v6: &AeCiphertext) -> PodAeCiphertextLegacy {
    PodAeCiphertextLegacy::from(v6.to_bytes())
}
