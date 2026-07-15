//! Common types for confidential transfer operations

use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use std::error::Error;

/// The native ZK ElGamal Proof program that verifies confidential-transfer proofs.
pub const ZK_PROOF_PROGRAM_ID: Pubkey =
    solana_sdk::pubkey!("ZkE1Gama1Proof11111111111111111111111111111");

/// Result type for confidential transfer operations
pub type CtResult<T> = Result<T, Box<dyn Error>>;

/// Signature result for single transactions
pub type SigResult = CtResult<Signature>;

/// Signature result for multi-transaction operations
pub type MultiSigResult = CtResult<Vec<Signature>>;

/// Progress events emitted by `transfer_confidential` so the demo UI can show
/// what's happening live during the multi-transaction transfer flow.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum TransferProgress {
    /// A logical phase has begun (proof generation, account creation, etc.).
    Phase { name: String, detail: String },
    /// A transaction landed; one of several per transfer.
    Signature { label: String, sig: String },
    /// Transfer completed successfully.
    Done { sigs: Vec<String> },
    /// Transfer failed at some stage.
    Error { message: String },
}

/// Optional sink for progress events. Pass `None` for non-interactive callers.
pub type ProgressSink<'a> = Option<&'a tokio::sync::broadcast::Sender<TransferProgress>>;

/// Best-effort send: never propagates send failure (no receivers is fine).
pub fn emit(sink: ProgressSink<'_>, ev: TransferProgress) {
    if let Some(tx) = sink {
        let _ = tx.send(ev);
    }
}
