//! Read and decrypt the balances on a confidential token account.
//!
//! Shared by the examples and demo flows so the ciphertext decoding and lo/hi
//! pending recombination live in exactly one place.

use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::{AeCiphertext, AeKey},
    elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use solana_zk_sdk_pod::encryption::elgamal::PodElGamalCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    extension::{
        confidential_transfer::ConfidentialTransferAccount, BaseStateWithExtensions,
        StateWithExtensions,
    },
    state::Account as TokenAccount,
};

/// The three balance buckets on a confidential account, all in base units.
#[derive(Clone, Copy, Debug)]
pub struct Balances {
    /// Visible to everyone on chain.
    pub public: u64,
    /// ElGamal-encrypted, credited by deposits/transfers, needs `apply_pending`.
    pub pending: u64,
    /// Spendable confidential balance (decrypted via the cheap AES path).
    pub available: u64,
}

impl Balances {
    pub fn total(&self) -> u64 {
        self.public + self.pending + self.available
    }
}

/// Decode an on-chain POD ElGamal ciphertext.
fn decode_ciphertext(field: &PodElGamalCiphertext, what: &str) -> CtResult<ElGamalCiphertext> {
    (*field)
        .try_into()
        .map_err(|e| format!("decode {what}: {e:?}").into())
}

/// Fetch `owner`'s confidential account for `mint` and decrypt every balance.
///
/// Pending is recovered via ElGamal (lo/hi split, recombined); available via
/// the AES decryptable balance. Encryption keys are derived from the owner's
/// signature, so `owner` must be the account authority.
pub fn read_balances(client: &RpcClient, owner: &dyn Signer, mint: &Pubkey) -> CtResult<Balances> {
    let token_account =
        get_associated_token_address_with_program_id(&owner.pubkey(), mint, &spl_token_2022::id());
    let elgamal_keypair = ElGamalKeypair::new_from_signer(owner, &token_account.to_bytes())?;
    let aes_key = AeKey::new_from_signer(owner, &token_account.to_bytes())?;

    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ext = account.get_extension::<ConfidentialTransferAccount>()?;

    let public = account.base.amount;

    let pending_lo = decode_ciphertext(&ext.pending_balance_lo, "pending_balance_lo")?
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_lo")?;
    let pending_hi = decode_ciphertext(&ext.pending_balance_hi, "pending_balance_hi")?
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or("decrypt pending_balance_hi")?;
    let pending = pending_lo + (pending_hi << 16);

    let decryptable: AeCiphertext = ext
        .decryptable_available_balance
        .try_into()
        .map_err(|e| format!("decode decryptable_available_balance: {e:?}"))?;
    let available = decryptable
        .decrypt(&aes_key)
        .ok_or("decrypt decryptable_available_balance")?;

    Ok(Balances {
        public,
        pending,
        available,
    })
}

/// Decrypt the available balance via the (expensive) ElGamal path, for callers
/// that want to confirm it matches the AES decryptable balance.
pub fn read_available_elgamal(
    client: &RpcClient,
    owner: &dyn Signer,
    mint: &Pubkey,
) -> CtResult<u64> {
    let token_account =
        get_associated_token_address_with_program_id(&owner.pubkey(), mint, &spl_token_2022::id());
    let elgamal_keypair = ElGamalKeypair::new_from_signer(owner, &token_account.to_bytes())?;
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ext = account.get_extension::<ConfidentialTransferAccount>()?;
    decode_ciphertext(&ext.available_balance, "available_balance")?
        .decrypt_u32(elgamal_keypair.secret())
        .ok_or_else(|| "decrypt available_balance (ElGamal)".into())
}
