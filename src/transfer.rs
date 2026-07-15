//! Confidential transfer between accounts.
//!
//! Generates the three transfer proofs (equality, ciphertext-validity, range)
//! with `spl-token-confidential-transfer-proof-generation = 0.6.0`
//! (solana-zk-sdk 6.0.1), pre-verifies each into a context state account, then
//! references those accounts in spl-token-2022 11.0.0's transfer ix via
//! `ProofLocation::ContextStateAccount`.

use crate::types::*;
use solana_address::Address;
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction;
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
use solana_zk_sdk_pod::encryption::{auth_encryption::PodAeCiphertext, elgamal::PodElGamalPubkey};
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
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::transfer_split_proof_data;
use std::mem::size_of;

pub(crate) const ZK_PROOF_PROGRAM_ID: Pubkey =
    solana_pubkey::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

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
    let sender_elgamal = ElGamalKeypair::new_from_signer(sender, &sender_token_account.to_bytes())
        .map_err(|e| format!("derive sender ElGamal: {e}"))?;
    let sender_aes = AeKey::new_from_signer(sender, &sender_token_account.to_bytes())
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
        "Generating equality, ciphertext-validity, and range proofs (zk-sdk 6.0.1)",
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

    phase(
        "create-proof-accounts",
        "Allocating + verifying 3 proof context state accounts",
    );

    let mut signatures: Vec<Signature> = Vec::new();

    // Build all three proof accounts up front so we can batch where possible.
    let equality_account = Keypair::new();
    let validity_account = Keypair::new();
    let range_account = Keypair::new();

    let equality_size = size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let validity_size =
        size_of::<ProofContextState<BatchedGroupedCiphertext3HandlesValidityProofContext>>();
    let range_size = size_of::<ProofContextState<BatchedRangeProofContext>>();

    let equality_rent = client.get_minimum_balance_for_rent_exemption(equality_size)?;
    let validity_rent = client.get_minimum_balance_for_rent_exemption(validity_size)?;
    let range_rent = client.get_minimum_balance_for_rent_exemption(range_size)?;

    let equality_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &equality_account.pubkey(),
        equality_rent,
        equality_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );
    let validity_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &validity_account.pubkey(),
        validity_rent,
        validity_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );
    let range_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &range_account.pubkey(),
        range_rent,
        range_size as u64,
        &ZK_PROOF_PROGRAM_ID,
    );

    // Use payer (not sender) as the context-state authority on all three
    // proof accounts. This keeps sender out of the verify txs' account_keys
    // — saves 32 bytes per tx, which is the difference between fitting and
    // overflowing the 1232-byte legacy size limit on `range_verify`. Closes
    // are then signed by payer too.
    let payer_addr: Address = payer.pubkey().to_bytes().into();
    let equality_verify_ix = ProofInstruction::VerifyCiphertextCommitmentEquality
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &Address::from(equality_account.pubkey().to_bytes()),
                context_state_authority: &payer_addr,
            }),
            &proof_data.equality_proof_data,
        );
    let validity_verify_ix = ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &Address::from(validity_account.pubkey().to_bytes()),
                context_state_authority: &payer_addr,
            }),
            &proof_data
                .ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
        );
    let range_verify_ix = ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &Address::from(range_account.pubkey().to_bytes()),
            context_state_authority: &payer_addr,
        }),
        &proof_data.range_proof_data,
    );

    // Tx 1: create all 3 proof accounts + verify the validity proof. The
    // validity proof's context data is the largest of eq/val (~544 vs ~320),
    // so it pairs with the small creates here; equality goes alongside the
    // transfer below where there's headroom.
    let sig = send_tx(
        client,
        &[
            equality_create_ix,
            validity_create_ix,
            range_create_ix,
            validity_verify_ix,
        ],
        &[payer, &equality_account, &validity_account, &range_account],
        &payer.pubkey(),
    )?;
    sig_event("create-proof-accounts+verify-validity", &sig);
    signatures.push(sig);

    // Tx 2: verify the range proof on its own. ~1006-byte verify ix; with
    // payer as authority and 3 account keys, lands at ~1206 bytes — under
    // Solana's 1232-byte legacy size limit, but only just.
    let sig = send_tx(client, &[range_verify_ix], &[payer], &payer.pubkey())?;
    sig_event("range-proof-account-verify", &sig);
    signatures.push(sig);

    phase("submit-transfer", "Submitting confidential transfer instruction");

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
        "verify-eq+transfer+close",
        "Verifying equality proof, submitting transfer, closing proof accounts",
    );

    // Tx 3: equality verify + transfer + 3 closes. Equality is the smallest
    // verify (~328-byte ix), and transfer + 3 closes is only ~210 bytes of ix
    // data, so this all fits in one tx (~1015 bytes). Close ixs use payer as
    // the context-state authority so only payer signs the closes; sender
    // still signs because it's the transfer's token-account authority.
    let close_eq = close_context_state(
        ContextStateInfo {
            context_state_account: &Address::from(equality_account.pubkey().to_bytes()),
            context_state_authority: &payer_addr,
        },
        &payer_addr,
    );
    let close_val = close_context_state(
        ContextStateInfo {
            context_state_account: &Address::from(validity_account.pubkey().to_bytes()),
            context_state_authority: &payer_addr,
        },
        &payer_addr,
    );
    let close_range = close_context_state(
        ContextStateInfo {
            context_state_account: &Address::from(range_account.pubkey().to_bytes()),
            context_state_authority: &payer_addr,
        },
        &payer_addr,
    );
    let sig = send_tx(
        client,
        &[
            equality_verify_ix,
            transfer_ix,
            close_eq,
            close_val,
            close_range,
        ],
        &[payer, sender],
        &payer.pubkey(),
    )?;
    sig_event("verify-eq+transfer+close", &sig);
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

/// Send a single tx, return the signature.
pub(crate) fn send_tx(
    client: &RpcClient,
    ixs: &[solana_instruction::Instruction],
    signers: &[&dyn Signer],
    payer: &Pubkey,
) -> CtResult<Signature> {
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(ixs, Some(payer), signers, blockhash);
    Ok(client.send_and_confirm_transaction(&tx)?)
}
