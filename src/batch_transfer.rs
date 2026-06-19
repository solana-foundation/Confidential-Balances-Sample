//! Batched confidential transfers from a *single* sender.
//!
//! ## Why the sending side is serial
//!
//! Every confidential transfer debits the sender's `available_balance`, which
//! lives on chain only as an opaque ElGamal ciphertext. Spending is a
//! read-modify-write against that ciphertext: the equality proof binds to the
//! *current* available-balance ciphertext, and the AES `decryptable_available_balance`
//! is overwritten with a fresh running cleartext. Two transfers generated
//! against the same starting ciphertext therefore cannot both land: whichever
//! lands first mutates the ciphertext, and the second's equality proof no
//! longer matches the value the token program recomputes. So N transfers from
//! one sender are inherently ordered.
//!
//! ## What "batching" actually buys us
//!
//! The sender holds the secret, so the entire chain of intermediate states can
//! be computed *offline* without a round trip per transfer. ElGamal ciphertexts
//! subtract homomorphically, and the proof-generation crate exposes the new
//! available-balance ciphertext it derives inside each proof (it is the
//! `ciphertext` field of the equality proof context). We feed that ciphertext
//! straight into the next transfer's proof:
//!
//! ```text
//! C0 = on-chain available balance
//! proof_i = transfer_split_proof_data(C_i, encrypt(running_i), amount_i, ...)
//! C_{i+1} = proof_i.equality_proof_data.context.ciphertext   // C_i ⊖ Enc(amount_i)
//! running_{i+1} = running_i - amount_i
//! ```
//!
//! [`prepare_legs`] runs that loop once, decrypting the balance a single time.
//! Two execution strategies then ship the prepared legs:
//!
//! * [`batch_transfer_atomic`] (option 1): pre-verify every leg's proofs into
//!   context state accounts, then submit ONE v0 transaction containing all N
//!   `Transfer` instructions. Same-tx instruction order makes the chained
//!   proofs validate deterministically. An Address Lookup Table compresses the
//!   account list so several legs fit, and a compute-budget bump clears the CU
//!   ceiling. Bounded by tx size / CU; this is the real "batch".
//!
//! * [`batch_transfer_pipelined`] (option 2): same offline proof generation,
//!   but submit each leg as its own confirmed transaction in sequence. No
//!   size/CU ceiling and unbounded fan-out, at the cost of one confirmation per
//!   leg. Legs must land in order or a later leg's proof goes stale.

use crate::transfer::{send_tx, ZK_PROOF_PROGRAM_ID};
use crate::types::*;
use solana_address::Address;
use solana_address_lookup_table_interface::instruction::{
    create_lookup_table, extend_lookup_table,
};
use solana_client::rpc_client::RpcClient;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::{v0, AddressLookupTableAccount, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_system_interface::instruction as system_instruction;
use solana_transaction::versioned::VersionedTransaction;
use solana_zk_elgamal_proof_interface::{
    instruction::{close_context_state, ContextStateInfo, ProofInstruction},
    proof_data::{
        BatchedGroupedCiphertext3HandlesValidityProofContext, BatchedRangeProofContext,
        CiphertextCommitmentEqualityProofContext, ZkProofData,
    },
    state::ProofContextState,
};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair, ElGamalPubkey},
};
use solana_zk_sdk_pod::encryption::{
    auth_encryption::PodAeCiphertext, elgamal::PodElGamalPubkey,
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
    state::{Account as TokenAccount, Mint},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::transfer::{
    transfer_split_proof_data, TransferProofData,
};
use std::mem::size_of;
use std::time::Duration;

/// One destination of a batched transfer.
#[derive(Clone, Copy, Debug)]
pub struct TransferLeg {
    pub recipient: Pubkey,
    pub amount: u64,
}

/// A leg with its proofs generated against the predicted chained sender state.
struct PreparedLeg {
    recipient_token_account: Pubkey,
    proof: TransferProofData,
    new_decryptable: PodAeCiphertext,
}

/// The three proof context accounts staged on chain for one leg.
struct StagedLeg {
    equality_account: Pubkey,
    validity_account: Pubkey,
    range_account: Pubkey,
}

/// Read the mint's optional auditor ElGamal pubkey.
fn fetch_auditor_pubkey(client: &RpcClient, mint: &Pubkey) -> CtResult<Option<ElGamalPubkey>> {
    let mint_acc_data = client.get_account(mint)?;
    let mint_acc = StateWithExtensions::<Mint>::unpack(&mint_acc_data.data)?;
    let mint_ext = mint_acc.get_extension::<ConfidentialTransferMint>()?;
    Option::<PodElGamalPubkey>::from(mint_ext.auditor_elgamal_pubkey)
        .map(|pod| {
            ElGamalPubkey::try_from(pod)
                .map_err(|e| format!("auditor ElGamal pubkey: {e:?}").into())
        })
        .transpose()
}

/// Read a configured account's ElGamal pubkey.
fn fetch_elgamal_pubkey(client: &RpcClient, token_account: &Pubkey) -> CtResult<ElGamalPubkey> {
    let acc_data = client.get_account(token_account)?;
    let acc = StateWithExtensions::<TokenAccount>::unpack(&acc_data.data)?;
    let ext = acc.get_extension::<ConfidentialTransferAccount>()?;
    ext.elgamal_pubkey
        .try_into()
        .map_err(|e| format!("recipient ElGamal pubkey: {e:?}").into())
}

/// Walk the legs once, generating each transfer's proofs against the sender
/// state predicted by the previous legs. Decrypts the available balance exactly
/// once; everything after is offline ciphertext arithmetic.
fn prepare_legs(
    client: &RpcClient,
    sender_token_account: &Pubkey,
    sender_elgamal: &ElGamalKeypair,
    sender_aes: &AeKey,
    mint: &Pubkey,
    legs: &[TransferLeg],
    auditor: Option<&ElGamalPubkey>,
) -> CtResult<Vec<PreparedLeg>> {
    let sender_acc_data = client.get_account(sender_token_account)?;
    let sender_acc = StateWithExtensions::<TokenAccount>::unpack(&sender_acc_data.data)?;
    let sender_ext = sender_acc.get_extension::<ConfidentialTransferAccount>()?;

    // Starting available-balance ciphertext (C0) and its cleartext value.
    let mut current_ct: ElGamalCiphertext = sender_ext
        .available_balance
        .try_into()
        .map_err(|e| format!("sender available balance: {e:?}"))?;
    let current_decryptable: AeCiphertext = sender_ext
        .decryptable_available_balance
        .try_into()
        .map_err(|e| format!("sender decryptable balance: {e:?}"))?;
    let mut running = current_decryptable
        .decrypt(sender_aes)
        .ok_or("decrypt sender available balance")?;

    let total: u64 = legs.iter().map(|l| l.amount).sum();
    if running < total {
        return Err(format!(
            "Insufficient confidential balance: have {running}, need {total} across {} legs",
            legs.len()
        )
        .into());
    }

    let mut prepared = Vec::with_capacity(legs.len());
    for leg in legs {
        let recipient_token_account = get_associated_token_address_with_program_id(
            &leg.recipient,
            mint,
            &spl_token_2022::id(),
        );
        let recipient_elgamal = fetch_elgamal_pubkey(client, &recipient_token_account)?;

        // The proof generator only reads the cleartext out of this AES
        // ciphertext, so a fresh encryption of `running` stands in for the
        // (randomized) on-chain ciphertext the previous leg would have written.
        let decryptable_in = sender_aes.encrypt(running);

        let proof = transfer_split_proof_data(
            &current_ct,
            &decryptable_in,
            leg.amount,
            sender_elgamal,
            sender_aes,
            &recipient_elgamal,
            auditor,
        )
        .map_err(|e| format!("transfer_split_proof_data: {e}"))?;

        running = running
            .checked_sub(leg.amount)
            .ok_or("leg amount exceeds running balance")?;
        let new_decryptable: PodAeCiphertext = sender_aes.encrypt(running).into();

        // Chain forward: the equality proof context holds C_i ⊖ Enc(amount_i),
        // exactly the available-balance ciphertext the chain will leave behind.
        let next_ct = proof.equality_proof_data.context_data().ciphertext;
        current_ct = next_ct
            .try_into()
            .map_err(|e| format!("chained available balance: {e:?}"))?;

        prepared.push(PreparedLeg {
            recipient_token_account,
            proof,
            new_decryptable,
        });
    }

    Ok(prepared)
}

/// Pre-verify a single leg's three proofs into context state accounts,
/// mirroring the single-transfer flow: one tx creates all three accounts and
/// verifies the validity proof, the oversized range proof verifies alone (it
/// only fits under the 1232-byte limit with payer as the context-state
/// authority), and the equality proof verifies in a third tx since the
/// transfer it would otherwise ride with happens later.
fn stage_leg(
    client: &RpcClient,
    payer: &dyn Signer,
    leg: &PreparedLeg,
    sigs: &mut Vec<Signature>,
) -> CtResult<StagedLeg> {
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

    let payer_addr: Address = payer.pubkey().to_bytes().into();
    let equality_verify_ix = ProofInstruction::VerifyCiphertextCommitmentEquality
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &Address::from(equality_account.pubkey().to_bytes()),
                context_state_authority: &payer_addr,
            }),
            &leg.proof.equality_proof_data,
        );
    let validity_verify_ix = ProofInstruction::VerifyBatchedGroupedCiphertext3HandlesValidity
        .encode_verify_proof(
            Some(ContextStateInfo {
                context_state_account: &Address::from(validity_account.pubkey().to_bytes()),
                context_state_authority: &payer_addr,
            }),
            &leg
                .proof
                .ciphertext_validity_proof_data_with_ciphertext
                .proof_data,
        );
    let range_verify_ix = ProofInstruction::VerifyBatchedRangeProofU128.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &Address::from(range_account.pubkey().to_bytes()),
            context_state_authority: &payer_addr,
        }),
        &leg.proof.range_proof_data,
    );

    // Tx 1: create all 3 proof accounts + verify the validity proof.
    sigs.push(send_tx(
        client,
        &[
            equality_create_ix,
            validity_create_ix,
            range_create_ix,
            validity_verify_ix,
        ],
        &[payer, &equality_account, &validity_account, &range_account],
        &payer.pubkey(),
    )?);

    // Tx 2: verify the range proof on its own (~1206 bytes, just under the
    // legacy tx size limit).
    sigs.push(send_tx(client, &[range_verify_ix], &[payer], &payer.pubkey())?);

    // Tx 3: verify the equality proof. In the single-transfer flow this rides
    // with the transfer ix, but here the transfers land later (potentially all
    // in one atomic tx), so it gets its own tx.
    sigs.push(send_tx(
        client,
        &[equality_verify_ix],
        &[payer],
        &payer.pubkey(),
    )?);

    Ok(StagedLeg {
        equality_account: equality_account.pubkey(),
        validity_account: validity_account.pubkey(),
        range_account: range_account.pubkey(),
    })
}

/// Build the `Transfer` instruction for a leg referencing its staged proofs.
fn transfer_ix_for(
    sender_token_account: &Pubkey,
    mint: &Pubkey,
    authority: &Pubkey,
    leg: &PreparedLeg,
    staged: &StagedLeg,
) -> CtResult<Instruction> {
    let equality_loc: ProofLocation<CiphertextCommitmentEqualityProofData> =
        ProofLocation::ContextStateAccount(&staged.equality_account);
    let validity_loc: ProofLocation<BatchedGroupedCiphertext3HandlesValidityProofData> =
        ProofLocation::ContextStateAccount(&staged.validity_account);
    let range_loc: ProofLocation<BatchedRangeProofU128Data> =
        ProofLocation::ContextStateAccount(&staged.range_account);

    inner_transfer(
        &spl_token_2022::id(),
        sender_token_account,
        mint,
        &leg.recipient_token_account,
        &leg.new_decryptable,
        &leg.proof.ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        &leg.proof.ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
        authority,
        &[],
        equality_loc,
        validity_loc,
        range_loc,
    )
    .map_err(|e| format!("inner_transfer: {e}").into())
}

/// Close a leg's proof context accounts. Payer is the context-state authority
/// on all of them, and reclaims the rent.
fn close_leg_ixs(payer: &Pubkey, staged: &StagedLeg) -> Vec<Instruction> {
    let payer_addr = Address::from(payer.to_bytes());
    let close_ctx = |ctx: &Pubkey| {
        close_context_state(
            ContextStateInfo {
                context_state_account: &Address::from(ctx.to_bytes()),
                context_state_authority: &payer_addr,
            },
            &payer_addr,
        )
    };
    vec![
        close_ctx(&staged.equality_account),
        close_ctx(&staged.validity_account),
        close_ctx(&staged.range_account),
    ]
}

// ----------------------------------------------------------------------------
// Option 2: pipelined (one confirmed transaction per leg)
// ----------------------------------------------------------------------------

/// Submit `legs` transfers from `sender` as a pipeline of confirmed
/// transactions: proofs are all generated offline up front, then each leg is
/// staged, transferred, and closed in order. No transaction-size or compute
/// ceiling, but one round of confirmation per leg.
pub async fn batch_transfer_pipelined(
    client: &RpcClient,
    payer: &dyn Signer,
    sender: &Keypair,
    mint: &Pubkey,
    legs: &[TransferLeg],
) -> MultiSigResult {
    let sender_token_account =
        get_associated_token_address_with_program_id(&sender.pubkey(), mint, &spl_token_2022::id());
    let sender_elgamal = ElGamalKeypair::new_from_signer(sender, &sender_token_account.to_bytes())?;
    let sender_aes = AeKey::new_from_signer(sender, &sender_token_account.to_bytes())?;
    let auditor = fetch_auditor_pubkey(client, mint)?;

    let prepared = prepare_legs(
        client,
        &sender_token_account,
        &sender_elgamal,
        &sender_aes,
        mint,
        legs,
        auditor.as_ref(),
    )?;

    let mut sigs = Vec::new();
    for (i, leg) in prepared.iter().enumerate() {
        let staged = stage_leg(client, payer, leg, &mut sigs)?;

        let transfer_ix =
            transfer_ix_for(&sender_token_account, mint, &sender.pubkey(), leg, &staged)?;
        let mut ixs = vec![transfer_ix];
        ixs.extend(close_leg_ixs(&payer.pubkey(), &staged));

        let sig = send_tx(client, &ixs, &[payer, sender], &payer.pubkey())?;
        sigs.push(sig);
        println!(
            "  leg {}/{}: {} -> {} ({} lamports of token) [{}]",
            i + 1,
            prepared.len(),
            sender.pubkey(),
            leg.recipient_token_account,
            legs[i].amount,
            sig
        );
    }

    println!(
        "✅ Pipelined batch transfer complete: {} legs in {} transactions",
        prepared.len(),
        sigs.len()
    );
    Ok(sigs)
}

// ----------------------------------------------------------------------------
// Option 1: atomic (all legs in one v0 transaction via an Address Lookup Table)
// ----------------------------------------------------------------------------

/// Submit all `legs` transfers from `sender` in a single atomic transaction.
///
/// Proofs are pre-verified into context state accounts (parallelizable, but
/// done sequentially here for clarity), an Address Lookup Table is created to
/// compress the account list, and one v0 transaction carries a compute-budget
/// bump plus every `Transfer` instruction. Because the instructions execute in
/// order within the transaction, the offline-chained proofs validate against
/// the exact intermediate ciphertexts each leg expects.
///
/// Bounded by transaction size and compute units: very large batches should
/// fall back to [`batch_transfer_pipelined`].
pub async fn batch_transfer_atomic(
    client: &RpcClient,
    payer: &dyn Signer,
    sender: &Keypair,
    mint: &Pubkey,
    legs: &[TransferLeg],
    compute_unit_limit: u32,
) -> MultiSigResult {
    let sender_token_account =
        get_associated_token_address_with_program_id(&sender.pubkey(), mint, &spl_token_2022::id());
    let sender_elgamal = ElGamalKeypair::new_from_signer(sender, &sender_token_account.to_bytes())?;
    let sender_aes = AeKey::new_from_signer(sender, &sender_token_account.to_bytes())?;
    let auditor = fetch_auditor_pubkey(client, mint)?;

    let prepared = prepare_legs(
        client,
        &sender_token_account,
        &sender_elgamal,
        &sender_aes,
        mint,
        legs,
        auditor.as_ref(),
    )?;

    // Stage every leg's proofs. These touch only fresh accounts, so they don't
    // conflict with each other and could be parallelized.
    let mut sigs = Vec::new();
    let mut staged_legs = Vec::with_capacity(prepared.len());
    for (i, leg) in prepared.iter().enumerate() {
        println!("  staging proofs for leg {}/{}", i + 1, prepared.len());
        let staged = stage_leg(client, payer, leg, &mut sigs)?;
        staged_legs.push(staged);
    }

    // Build an Address Lookup Table holding the accounts the transfers
    // reference, so the v0 message can address them by 1-byte index.
    // `create_lookup_table` derives the LUT address from a slot that must be
    // in the SlotHashes sysvar as seen at execution; a confirmed-commitment
    // slot can be too fresh, so anchor to the finalized slot.
    let recent_slot =
        client.get_slot_with_commitment(solana_commitment_config::CommitmentConfig::finalized())?;
    let (create_ix, lut_address) =
        create_lookup_table(payer.pubkey(), payer.pubkey(), recent_slot);

    let mut lut_addresses: Vec<Pubkey> =
        vec![spl_token_2022::id(), *mint, sender_token_account];
    for (leg, staged) in prepared.iter().zip(&staged_legs) {
        lut_addresses.push(leg.recipient_token_account);
        lut_addresses.push(staged.equality_account);
        lut_addresses.push(staged.validity_account);
        lut_addresses.push(staged.range_account);
    }
    let extend_ix = extend_lookup_table(
        lut_address,
        payer.pubkey(),
        Some(payer.pubkey()),
        lut_addresses.clone(),
    );

    sigs.push(send_tx(client, &[create_ix], &[payer], &payer.pubkey())?);
    sigs.push(send_tx(client, &[extend_ix], &[payer], &payer.pubkey())?);
    println!("  created + extended lookup table {lut_address}");

    // A lookup table is only usable in a transaction processed in a later slot
    // than the one its last extension landed in. Wait for the slot to advance.
    wait_for_slot_advance(client).await?;

    // Assemble the atomic transaction: compute budget + one Transfer per leg.
    let mut ixs = vec![ComputeBudgetInstruction::set_compute_unit_limit(
        compute_unit_limit,
    )];
    for (leg, staged) in prepared.iter().zip(&staged_legs) {
        ixs.push(transfer_ix_for(
            &sender_token_account,
            mint,
            &sender.pubkey(),
            leg,
            staged,
        )?);
    }

    let alt = AddressLookupTableAccount {
        key: lut_address,
        addresses: lut_addresses,
    };
    let blockhash = client.get_latest_blockhash()?;
    let message = v0::Message::try_compile(&payer.pubkey(), &ixs, &[alt], blockhash)
        .map_err(|e| format!("compile v0 message: {e}"))?;
    let tx = VersionedTransaction::try_new(VersionedMessage::V0(message), &[payer, sender])
        .map_err(|e| format!("sign v0 transaction: {e}"))?;

    let atomic_sig = client.send_and_confirm_transaction(&tx)?;
    sigs.push(atomic_sig);
    println!(
        "✅ Atomic batch transfer complete: {} legs in 1 transaction [{}]",
        prepared.len(),
        atomic_sig
    );

    // Reclaim rent: close every leg's proof context accounts. The transfers
    // already consumed the verified proofs.
    for staged in &staged_legs {
        let ixs = close_leg_ixs(&payer.pubkey(), staged);
        sigs.push(send_tx(client, &ixs, &[payer], &payer.pubkey())?);
    }

    Ok(sigs)
}

/// Poll until the cluster slot advances past the current one, so a freshly
/// extended lookup table becomes usable.
async fn wait_for_slot_advance(client: &RpcClient) -> CtResult<()> {
    let start = client.get_slot()?;
    for _ in 0..40 {
        if client.get_slot()? > start {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    Err("lookup table did not warm up: slot never advanced".into())
}
