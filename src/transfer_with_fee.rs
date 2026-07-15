//! Confidential transfer on a mint with confidential transfer fees.
//!
//! The fee-aware transfer needs five proofs instead of three: equality,
//! transfer-amount ciphertext validity (3 handles), percentage-with-cap (the
//! fee actually matches the mint's fee parameters), fee ciphertext validity
//! (2 handles: recipient + withdraw-withheld authority), and a U256 range
//! proof covering the amount, the fee, and the remaining balance together.
//!
//! Each proof is pre-verified into a context state account and the transfer
//! ix references them via `ProofLocation::ContextStateAccount`. The U256
//! range proof is the catch: its verify instruction is ~1250 bytes of proof
//! data alone, over the 1232-byte transaction limit, so it cannot be sent
//! inline at all. Instead the proof bytes are staged into an spl-record
//! account across multiple write transactions and verified from there with
//! `encode_verify_proof_from_account`.

use crate::transfer::{send_tx, ZK_PROOF_PROGRAM_ID};
use crate::types::*;
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_zk_elgamal_proof_interface::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::{
        BatchedGroupedCiphertext2HandlesValidityProofContext,
        BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
        CiphertextCommitmentEqualityProofContext, PercentageWithCapProofContext,
    },
    state::ProofContextState,
};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
};
use solana_zk_sdk_pod::encryption::{auth_encryption::PodAeCiphertext, elgamal::PodElGamalPubkey};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::{
                inner_transfer_with_fee, BatchedGroupedCiphertext2HandlesValidityProofData,
                BatchedGroupedCiphertext3HandlesValidityProofData, BatchedRangeProofU256Data,
                CiphertextCommitmentEqualityProofData, PercentageWithCapProofData,
            },
            ConfidentialTransferAccount, ConfidentialTransferMint,
        },
        confidential_transfer_fee::ConfidentialTransferFeeConfig,
        transfer_fee::TransferFeeConfig,
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer_with_fee::transfer_with_fee_split_proof_data;
use std::mem::size_of;

/// Byte offset of the proof data inside an spl-record account
/// (`RecordData::WRITABLE_START_INDEX`: 1-byte version + 32-byte authority).
const RECORD_PROOF_OFFSET: u32 = 33;

/// Per-tx write payloads for staging the proof into a record account, sized to
/// stay under the 1232-byte tx limit. The first write also carries
/// create_account + initialize, so it gets a smaller budget; the final write
/// also carries the context create + verify-from-account, which it has room
/// for.
const RECORD_FIRST_CHUNK: usize = 750;
const RECORD_WRITE_CHUNK: usize = 900;

/// Transfer `amount` confidentially on a mint carrying `TransferFeeConfig` +
/// `ConfidentialTransferFeeConfig`. The fee (per the mint's parameters for
/// the current epoch) is withheld on the recipient account, encrypted under
/// the mint's withdraw-withheld authority ElGamal key.
pub async fn transfer_confidential_with_fee(
    client: &RpcClient,
    payer: &dyn Signer,
    sender: &Keypair,
    mint: &Pubkey,
    recipient: &Pubkey,
    amount: u64,
) -> MultiSigResult {
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

    // ----- Mint state: auditor key, fee parameters, withheld authority key -----
    let mint_acc_data = client.get_account(mint)?;
    let mint_acc = StateWithExtensions::<Mint>::unpack(&mint_acc_data.data)?;

    let mint_ext = mint_acc.get_extension::<ConfidentialTransferMint>()?;
    let auditor_elgamal_pubkey: Option<ElGamalPubkey> =
        Option::<PodElGamalPubkey>::from(mint_ext.auditor_elgamal_pubkey)
            .map(|pod| {
                ElGamalPubkey::try_from(pod).map_err(|e| format!("auditor ElGamal pubkey: {e:?}"))
            })
            .transpose()?;

    let fee_config = mint_acc.get_extension::<TransferFeeConfig>()?;
    let epoch = client.get_epoch_info()?.epoch;
    let epoch_fee = fee_config.get_epoch_fee(epoch);
    let fee_rate_basis_points: u16 = epoch_fee.transfer_fee_basis_points.into();
    let maximum_fee: u64 = epoch_fee.maximum_fee.into();

    let ct_fee_config = mint_acc.get_extension::<ConfidentialTransferFeeConfig>()?;
    let withheld_authority_elgamal_pubkey: ElGamalPubkey = ct_fee_config
        .withdraw_withheld_authority_elgamal_pubkey
        .try_into()
        .map_err(|e| format!("withdraw-withheld authority ElGamal pubkey: {e:?}"))?;

    // ----- Sender keys and balances -----
    let sender_elgamal = ElGamalKeypair::new_from_signer(sender, &sender_token_account.to_bytes())
        .map_err(|e| format!("derive sender ElGamal: {e}"))?;
    let sender_aes = AeKey::new_from_signer(sender, &sender_token_account.to_bytes())
        .map_err(|e| format!("derive sender AES: {e}"))?;

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

    println!(
        "🔐 Generating transfer-with-fee proofs for {amount} base units \
         (fee: {fee_rate_basis_points} bps, max {maximum_fee})..."
    );
    let proof_data = transfer_with_fee_split_proof_data(
        &current_available,
        &current_decryptable,
        amount,
        &sender_elgamal,
        &sender_aes,
        &recipient_elgamal_pubkey,
        auditor_elgamal_pubkey.as_ref(),
        &withheld_authority_elgamal_pubkey,
        fee_rate_basis_points,
        maximum_fee,
    )
    .map_err(|e| format!("transfer_with_fee_split_proof_data: {e}"))?;

    // ----- Stage the five proofs into context state accounts -----
    let mut signatures: Vec<Signature> = Vec::new();

    let equality_account = Keypair::new();
    let validity_account = Keypair::new();
    let fee_sigma_account = Keypair::new();
    let fee_validity_account = Keypair::new();
    let range_account = Keypair::new();

    let payer_addr: Address = payer.pubkey().to_bytes().into();
    let equality_addr = Address::from(equality_account.pubkey().to_bytes());
    let validity_addr = Address::from(validity_account.pubkey().to_bytes());
    let fee_sigma_addr = Address::from(fee_sigma_account.pubkey().to_bytes());
    let fee_validity_addr = Address::from(fee_validity_account.pubkey().to_bytes());
    let range_addr = Address::from(range_account.pubkey().to_bytes());
    // Tx 1: create all five context accounts (their verify ixs won't all fit
    // alongside, but the creates are small and share one tx fine).
    let create_ix =
        |account: &Keypair, space: usize| -> CtResult<solana_instruction::Instruction> {
            let rent = client.get_minimum_balance_for_rent_exemption(space)?;
            Ok(system_instruction::create_account(
                &payer.pubkey(),
                &account.pubkey(),
                rent,
                space as u64,
                &ZK_PROOF_PROGRAM_ID,
            ))
        };
    let sig = send_tx(
        client,
        &[
            create_ix(
                &equality_account,
                size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>(),
            )?,
            create_ix(
                &validity_account,
                size_of::<
                    ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>,
                >(),
            )?,
            create_ix(
                &fee_sigma_account,
                size_of::<ProofContextState<PercentageWithCapProofContext>>(),
            )?,
            create_ix(
                &fee_validity_account,
                size_of::<
                    ProofContextState<BatchedGroupedCiphertext2HandlesValidityProofContext>,
                >(),
            )?,
            create_ix(
                &range_account,
                size_of::<ProofContextState<BatchedRangeProofContext>>(),
            )?,
        ],
        &[
            payer,
            &equality_account,
            &validity_account,
            &fee_sigma_account,
            &fee_validity_account,
            &range_account,
        ],
        &payer.pubkey(),
    )?;
    signatures.push(sig);
    println!("  created 5 proof context accounts [{sig}]");

    // Txs 2-5: verify the four "small" proofs, one per tx. Some pairs would
    // fit together, but one-per-tx keeps every tx comfortably under the size
    // limit for all fee parameter shapes.
    let equality_verify_ix = ProofInstruction::VerifyCiphertextCommitmentEquality
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &equality_addr,
                context_state_authority: &payer_addr,
            }),
            &proof_data.equality_proof_data,
        );
    let validity_verify_ix = ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &validity_addr,
                context_state_authority: &payer_addr,
            }),
            &proof_data
                .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
        );
    let fee_sigma_verify_ix = ProofInstruction::VerifyPercentageWithCap.encode_verify_proof(
        Some(ContextStateInfo {
                context_state_account: &fee_sigma_addr,
                context_state_authority: &payer_addr,
            }),
        &proof_data.percentage_with_cap_proof_data,
    );
    let fee_validity_verify_ix = ProofInstruction::VerifyBatchedGroupedCiphertext2HandlesValidity
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &fee_validity_addr,
                context_state_authority: &payer_addr,
            }),
            &proof_data.fee_ciphertext_validity_proof_data,
        );
    for (label, ix) in [
        ("equality", equality_verify_ix),
        ("transfer-amount validity", validity_verify_ix),
        ("fee percentage-with-cap", fee_sigma_verify_ix),
        ("fee validity", fee_validity_verify_ix),
    ] {
        let sig = send_tx(client, &[ix], &[payer], &payer.pubkey())?;
        signatures.push(sig);
        println!("  verified {label} proof [{sig}]");
    }

    // U256 range proof: too big for any single tx, so stage the proof bytes
    // through an spl-record account and verify from there. The final record
    // write carries the verify-from-account ix.
    let record_account = Keypair::new();
    let range_verify_ix = ProofInstruction::VerifyBatchedRangeProofU256
        .encode_verify_proof_from_account(
            Some(ContextStateInfo {
                context_state_account: &range_addr,
                context_state_authority: &payer_addr,
            }),
            &Address::from(record_account.pubkey().to_bytes()),
            RECORD_PROOF_OFFSET,
        );
    let record_sigs = stage_proof_record(
        client,
        payer,
        &record_account,
        bytemuck::bytes_of(&proof_data.range_proof_data),
        &[range_verify_ix],
        &[],
    )?;
    println!(
        "  staged + verified U256 range proof via record account ({} txs)",
        record_sigs.len()
    );
    signatures.extend(record_sigs);

    // ----- Transfer with fee, then close everything -----
    let current_avail_plaintext = current_decryptable
        .decrypt(&sender_aes)
        .ok_or("decrypt current available")?;
    let new_avail_plaintext = current_avail_plaintext
        .checked_sub(amount)
        .ok_or("insufficient available balance")?;
    let new_decryptable: PodAeCiphertext = sender_aes.encrypt(new_avail_plaintext).into();

    let equality_loc: ProofLocation<CiphertextCommitmentEqualityProofData> =
        ProofLocation::ContextStateAccount(&equality_account.pubkey());
    let validity_loc: ProofLocation<BatchedGroupedCiphertext3HandlesValidityProofData> =
        ProofLocation::ContextStateAccount(&validity_account.pubkey());
    let fee_sigma_loc: ProofLocation<PercentageWithCapProofData> =
        ProofLocation::ContextStateAccount(&fee_sigma_account.pubkey());
    let fee_validity_loc: ProofLocation<BatchedGroupedCiphertext2HandlesValidityProofData> =
        ProofLocation::ContextStateAccount(&fee_validity_account.pubkey());
    let range_loc: ProofLocation<BatchedRangeProofU256Data> =
        ProofLocation::ContextStateAccount(&range_account.pubkey());

    let transfer_ix = inner_transfer_with_fee(
        &spl_token_2022::id(),
        &sender_token_account,
        mint,
        &recipient_token_account,
        &new_decryptable,
        &proof_data
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_lo,
        &proof_data
            .transfer_amount_ciphertext_validity_proof_data_with_ciphertext
            .ciphertext_hi,
        &sender.pubkey(),
        &[],
        equality_loc,
        validity_loc,
        fee_sigma_loc,
        fee_validity_loc,
        range_loc,
    )?;

    // The fee-aware transfer burns considerably more compute than the default
    // 200k-per-ix budget, so bump the limit.
    let compute_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    let close_ctx = |account_addr: &Address| {
        close_context_state(
            ContextStateInfo {
                context_state_account: account_addr,
                context_state_authority: &payer_addr,
            },
            &payer_addr,
        )
    };
    let close_record_ix = spl_record::instruction::close_account(
        &record_account.pubkey(),
        &payer.pubkey(),
        &payer.pubkey(),
    );

    let sig = send_tx(
        client,
        &[
            compute_ix,
            transfer_ix,
            close_ctx(&equality_addr),
            close_ctx(&validity_addr),
            close_ctx(&fee_sigma_addr),
            close_ctx(&fee_validity_addr),
            close_ctx(&range_addr),
            close_record_ix,
        ],
        &[payer, sender],
        &payer.pubkey(),
    )?;
    signatures.push(sig);

    println!(
        "✅ Confidential transfer with fee complete with {} transactions [{}]",
        signatures.len(),
        sig
    );
    Ok(signatures)
}

/// Create an spl-record account owned by `payer` (as record authority) and
/// write `proof_bytes` into it in tx-sized chunks. The first tx allocates +
/// initializes + writes the first chunk; subsequent chunks are write-only.
/// `trailing_ixs` (with `trailing_signers`) are appended to the final write tx
/// so the caller's verify-from-account rides along for free. Returns one
/// signature per transaction sent.
fn stage_proof_record(
    client: &RpcClient,
    payer: &dyn Signer,
    record_account: &Keypair,
    proof_bytes: &[u8],
    trailing_ixs: &[solana_instruction::Instruction],
    trailing_signers: &[&dyn Signer],
) -> CtResult<Vec<Signature>> {
    let space = proof_bytes.len() + RECORD_PROOF_OFFSET as usize;
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    if proof_bytes.is_empty() {
        return Err("proof had no bytes to stage".into());
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
