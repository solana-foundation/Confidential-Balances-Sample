//! Withdraw tokens from confidential balance to public balance (bypass mode).
//!
//! Generates the equality + range proofs using
//! `spl-token-confidential-transfer-proof-generation = 0.6.0`
//! (`solana-zk-sdk = 6.0.1`), pre-verifies each into a context state account,
//! then references those accounts in `spl-token-2022 = 10.0.0`'s withdraw ix
//! via `ProofLocation::ContextStateAccount`.

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
    proof_data::{BatchedRangeProofContext, CiphertextCommitmentEqualityProofContext},
    state::ProofContextState,
};
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext as PodElGamalCiphertextV6;
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
    solana_zk_sdk::encryption::pod::auth_encryption::PodAeCiphertext as PodAeCiphertextLegacy,
    state::Account as TokenAccount,
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use spl_token_confidential_transfer_proof_generation::withdraw::withdraw_proof_data;
use std::mem::size_of;

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

    // 4.0 PodElGamalCiphertext → 6.0.1 → ElGamalCiphertext.
    let available_v6: PodElGamalCiphertextV6 = PodElGamalCiphertextV6(
        bytemuck::bytes_of(&ct_extension.available_balance)
            .try_into()
            .map_err(|_| "available_balance size")?,
    );
    let available_balance: ElGamalCiphertext = available_v6
        .try_into()
        .map_err(|e| format!("decode available_balance: {e:?}"))?;

    // Read the plaintext balance from the AES-encrypted decryptable balance.
    // ElGamal's decrypt_u32 only recovers values up to 2^32 raw units, so it
    // fails for realistic balances; the AES field has no such limit.
    let decryptable_bytes: [u8; 36] =
        bytemuck::bytes_of(&ct_extension.decryptable_available_balance)
            .try_into()
            .map_err(|_| "decryptable_available_balance size")?;
    let current_available = AeCiphertext::from_bytes(&decryptable_bytes)
        .ok_or("decode decryptable_available_balance")?
        .decrypt(&aes_key)
        .ok_or("decrypt available balance")?;

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
    let new_decryptable_v6 = aes_key.encrypt(new_available);
    let new_decryptable_legacy: PodAeCiphertextLegacy =
        PodAeCiphertextLegacy::from(new_decryptable_v6.to_bytes());

    // ----- Pre-verify equality proof into a context state account -----
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
                context_state_authority: &Address::from(authority.pubkey().to_bytes()),
            }),
            &proof_data.equality_proof_data,
        );

    let mut signatures: Vec<Signature> = Vec::new();
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[equality_create_ix, equality_verify_ix],
        Some(&payer.pubkey()),
        &[payer, authority, &equality_account],
        blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&tx)?);

    // ----- Pre-verify range proof into a context state account -----
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
    let range_verify_ix = ProofInstruction::VerifyBatchedRangeProofU64.encode_verify_proof(
        Some(ContextStateInfo {
            context_state_account: &Address::from(range_account.pubkey().to_bytes()),
            context_state_authority: &Address::from(authority.pubkey().to_bytes()),
        }),
        &proof_data.range_proof_data,
    );

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[range_create_ix, range_verify_ix],
        Some(&payer.pubkey()),
        &[payer, authority, &range_account],
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
        &new_decryptable_legacy,
        &authority.pubkey(),
        &[&authority.pubkey()],
        equality_loc,
        range_loc,
    )?;

    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &withdraw_ixs,
        Some(&payer.pubkey()),
        &[payer, authority],
        blockhash,
    );
    signatures.push(client.send_and_confirm_transaction(&tx)?);

    // ----- Close the two proof context state accounts -----
    for account in [&equality_account, &range_account] {
        let close_ix = close_context_state(
            ContextStateInfo {
                context_state_account: &Address::from(account.pubkey().to_bytes()),
                context_state_authority: &Address::from(authority.pubkey().to_bytes()),
            },
            &Address::from(payer.pubkey().to_bytes()),
        );
        let blockhash = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[close_ix],
            Some(&payer.pubkey()),
            &[payer, authority],
            blockhash,
        );
        signatures.push(client.send_and_confirm_transaction(&tx)?);
    }

    println!(
        "✅ Withdrew {} tokens to public balance ({} txs). Remaining confidential: {}",
        amount,
        signatures.len(),
        new_available
    );
    // Return the withdraw ix signature (index 2 in the sequence).
    Ok(signatures[2])
}
