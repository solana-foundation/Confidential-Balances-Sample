//! Withdraw tokens from confidential balance to public balance.
//!
//! Generates the equality + range proofs with
//! `spl-token-confidential-transfer-proof-generation = 0.6.0`
//! (solana-zk-sdk 6.0.1), pre-verifies each into a context state account,
//! then references those accounts in spl-token-2022 11.0.0's withdraw ix
//! via `ProofLocation::ContextStateAccount`.

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
    proof_data::{BatchedRangeProofContext, CiphertextCommitmentEqualityProofContext},
    state::ProofContextState,
};
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::auth_encryption::PodAeCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::{
            instruction::{
                withdraw, BatchedRangeProofU64Data, CiphertextCommitmentEqualityProofData,
            },
            ConfidentialTransferAccount,
        },
        BaseStateWithExtensions, StateWithExtensions,
    },
    state::Account as TokenAccount,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::withdraw::withdraw_proof_data;
use std::mem::size_of;

const ZK_PROOF_PROGRAM_ID: Pubkey =
    solana_pubkey::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

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

    let elgamal_keypair = ElGamalKeypair::new_from_signer(authority, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(authority, &token_account.to_bytes())?;

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

    // ----- Pre-verify the proofs into context state accounts -----
    // Same packing as the transfer flow: the creates + the small equality
    // verify share one tx, and the range verify gets its own tx (the verify
    // ix carries the whole proof, so pairing it with anything else overflows
    // the 1232-byte tx size limit). Payer is the context-state authority so
    // the verify txs don't carry the token authority's key.
    let equality_account = Keypair::new();
    let range_account = Keypair::new();

    let equality_size = size_of::<ProofContextState<CiphertextCommitmentEqualityProofContext>>();
    let equality_rent = client.get_minimum_balance_for_rent_exemption(equality_size)?;
    let range_size = size_of::<ProofContextState<BatchedRangeProofContext>>();
    let range_rent = client.get_minimum_balance_for_rent_exemption(range_size)?;

    let equality_create_ix = system_instruction::create_account(
        &payer.pubkey(),
        &equality_account.pubkey(),
        equality_rent,
        equality_size as u64,
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
            &proof_data.equality_proof_data,
        );
    let range_verify_ix = ProofInstruction::VerifyBatchedRangeProofU64.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &Address::from(range_account.pubkey().to_bytes()),
            context_state_authority: &payer_addr,
        }),
        &proof_data.range_proof_data,
    );

    let mut signatures: Vec<Signature> = Vec::new();

    // Tx 1: create both proof accounts + verify the equality proof.
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[equality_create_ix, range_create_ix, equality_verify_ix],
        Some(&payer.pubkey()),
        &[payer, &equality_account, &range_account],
        blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&tx)?);

    // Tx 2: verify the range proof on its own.
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[range_verify_ix],
        Some(&payer.pubkey()),
        &[payer],
        blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&tx)?);

    // ----- Submit the withdraw ix referencing both context state accounts -----
    let equality_loc: ProofLocation<CiphertextCommitmentEqualityProofData> =
        ProofLocation::ContextStateAccount(&equality_account.pubkey());
    let range_loc: ProofLocation<BatchedRangeProofU64Data> =
        ProofLocation::ContextStateAccount(&range_account.pubkey());

    let withdraw_ixs = withdraw(
        &spl_token_2022::id(),
        &token_account,
        mint,
        amount,
        decimals,
        &new_decryptable,
        &authority.pubkey(),
        &[&authority.pubkey()],
        equality_loc,
        range_loc,
    )?;

    // Tx 3: withdraw + close both proof accounts. Payer is the context-state
    // authority on the closes; the token authority signs for the withdraw.
    let close_eq = close_context_state(
        ContextStateInfo {
            context_state_account: &Address::from(equality_account.pubkey().to_bytes()),
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
    let mut ixs = withdraw_ixs;
    ixs.push(close_eq);
    ixs.push(close_range);

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &ixs,
        Some(&payer.pubkey()),
        &[payer, authority],
        blockhash,
    );
    let withdraw_sig = client.send_and_confirm_transaction(&tx)?;
    signatures.push(withdraw_sig);

    println!(
        "✅ Withdrew {} tokens to public balance ({} txs). Remaining confidential: {}",
        amount,
        signatures.len(),
        new_available
    );
    Ok(withdraw_sig)
}
