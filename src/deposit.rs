//! Deposit tokens into confidential balance

use crate::send::{send_v1_tx, CU_LIMIT_DEFAULT};
use crate::types::*;
use solana_client::rpc_client::RpcClient;
use solana_signer::Signer;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::extension::confidential_transfer::instruction::deposit;

/// Deposit tokens from public balance to pending confidential balance
///
/// After deposit, tokens are in the "pending" state and must be applied
/// using apply_pending_balance before they can be used in transfers.
///
/// # Arguments
/// * `client` - RPC client
/// * `authority` - Account owner/authority
/// * `mint` - Token mint pubkey
/// * `amount` - Amount to deposit (in base units)
/// * `decimals` - Token decimals
pub async fn deposit_to_confidential(
    client: &RpcClient,
    payer: &dyn Signer,
    authority: &dyn Signer,
    mint: &solana_pubkey::Pubkey,
    amount: u64,
    decimals: u8,
) -> SigResult {
    let token_account = get_associated_token_address_with_program_id(
        &authority.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Create deposit instruction
    let deposit_ix = deposit(
        &spl_token_2022::id(),
        &token_account,
        mint,
        amount,
        decimals,
        &authority.pubkey(),
        &[&authority.pubkey()],
    )?;

    let signature = send_v1_tx(
        client,
        &[deposit_ix],
        &payer.pubkey(),
        &[payer, authority],
        CU_LIMIT_DEFAULT,
    )?;
    println!("✅ Deposited {} tokens to pending balance: {}", amount, signature);

    Ok(signature)
}
