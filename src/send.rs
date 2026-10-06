//! Shared transaction send paths.
//!
//! Single-transfer, withdraw, configure, and setup flows go out as v1
//! transactions (SIMD-0385): 4096-byte limit, compute budget carried in the
//! message header's `TransactionConfig` rather than ComputeBudget instructions
//! (those are ignored under v1). The batch and fee flows keep legacy/v0
//! transactions: batches lean on Address Lookup Tables, which v1 does not
//! carry, and both pre-verify their proofs into context state accounts.

use crate::types::CtResult;
use solana_client::rpc_client::RpcClient;
use solana_message::{v1, v1::TransactionConfig, VersionedMessage};
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::{versioned::VersionedTransaction, Transaction};

pub const ZK_PROOF_PROGRAM_ID: Pubkey =
    solana_pubkey::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

/// Single-ix operations: deposit, apply-pending, mint/ATA setup.
pub const CU_LIMIT_DEFAULT: u32 = 100_000;
/// Transfer + 3 inline proofs; ~238k measured on devnet, mostly the range proof.
pub const CU_LIMIT_TRANSFER: u32 = 350_000;
/// Withdraw + 2 inline proofs (equality 6.4k, range-U64 111k).
pub const CU_LIMIT_WITHDRAW: u32 = 200_000;
/// Realloc + configure + pubkey-validity proof (2.6k).
pub const CU_LIMIT_CONFIGURE: u32 = 80_000;

// v1 defaults unset config bits to 0 (not the legacy defaults), so both the
// CU limit and the loaded-accounts-data-size limit must always be set.
const LOADED_ACCOUNTS_DATA_SIZE: u32 = 64 * 1024 * 1024;

/// Build, sign, and send one v1 transaction; block until confirmed.
pub fn send_v1_tx(
    client: &RpcClient,
    ixs: &[solana_instruction::Instruction],
    payer: &Pubkey,
    signers: &[&dyn Signer],
    cu_limit: u32,
) -> CtResult<Signature> {
    let config = TransactionConfig::empty()
        .with_compute_unit_limit(cu_limit)
        .with_loaded_accounts_data_size_limit(LOADED_ACCOUNTS_DATA_SIZE);
    let blockhash = client.get_latest_blockhash()?;
    let message = v1::Message::try_compile_with_config(payer, ixs, blockhash, config)?;
    let tx = VersionedTransaction::try_new(VersionedMessage::V1(message), signers)?;
    Ok(client.send_and_confirm_transaction(&tx)?)
}

/// Build, sign, and send one legacy transaction; block until confirmed.
/// Used by the batch and fee flows, whose verify instructions are sized
/// against the 1232-byte legacy limit.
pub fn send_legacy_tx(
    client: &RpcClient,
    ixs: &[solana_instruction::Instruction],
    signers: &[&dyn Signer],
    payer: &Pubkey,
) -> CtResult<Signature> {
    let blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(ixs, Some(payer), signers, blockhash);
    Ok(client.send_and_confirm_transaction(&tx)?)
}
