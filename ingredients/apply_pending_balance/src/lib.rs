use std::{error::Error, sync::Arc};

use solana_sdk::{signer::Signer, transaction::Transaction};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    error::TokenError,
    extension::{
        confidential_transfer::account_info::ApplyPendingBalanceAccountInfo,
        BaseStateWithExtensions,
    },
    solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
};
use spl_token_2022_interface::extension::confidential_transfer::{
    instruction, ConfidentialTransferAccount,
};
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::Token,
};
use utils::{
    get_non_blocking_rpc_client, get_or_create_keypair, get_rpc_client, load_value,
    print_transaction_url,
};

pub async fn apply_pending_balance(
    token_account_authority: &dyn Signer,
) -> Result<(), Box<dyn Error>> {
    let fee_payer_keypair = Arc::new(get_or_create_keypair("fee_payer_keypair")?);
    let client = get_rpc_client()?;
    let mint = get_or_create_keypair("mint")?;
    let decimals = load_value("mint_decimals")?;

    let token_account_pubkey = get_associated_token_address_with_program_id(
        &token_account_authority.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    let sender_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&token_account_authority, &token_account_pubkey.to_bytes())
            .unwrap();
    let sender_aes_key =
        AeKey::new_from_signer(&token_account_authority, &token_account_pubkey.to_bytes()).unwrap();

    // The "pending" balance must be applied to "available" balance before it can be transferred

    // A "non-blocking" RPC client (for async calls)
    let token = {
        let rpc_client = get_non_blocking_rpc_client()?;

        let program_client =
            ProgramRpcClient::new(Arc::new(rpc_client), ProgramRpcClientSendTransaction);

        // Create a "token" client, to use various helper functions for Token Extensions
        Token::new(
            Arc::new(program_client),
            &spl_token_2022::id(),
            &mint.pubkey(),
            Some(decimals),
            fee_payer_keypair.clone(),
        )
    };

    // Get sender token account data
    let token_account_info = token.get_account_info(&token_account_pubkey).await?;

    // Unpack the ConfidentialTransferAccount extension portion of the token account data
    let confidential_transfer_account =
        token_account_info.get_extension::<ConfidentialTransferAccount>()?;

    // ConfidentialTransferAccount extension information needed to construct an `ApplyPendingBalance` instruction.
    let apply_pending_balance_account_info =
        ApplyPendingBalanceAccountInfo::new(confidential_transfer_account);

    // Return the number of times the pending balance has been credited
    let expected_pending_balance_credit_counter =
        apply_pending_balance_account_info.pending_balance_credit_counter();

    // Update the decryptable available balance (add pending balance to available balance)
    let new_decryptable_available_balance = apply_pending_balance_account_info
        .new_decryptable_available_balance(&sender_elgamal_keypair.secret(), &sender_aes_key)
        .map_err(|_| TokenError::AccountDecryption)?;

    // Create a `ApplyPendingBalance` instruction
    let apply_pending_balance_instruction = instruction::apply_pending_balance(
        &spl_token_2022::id(),
        &token_account_pubkey,                     // Token account
        expected_pending_balance_credit_counter, // Expected number of times the pending balance has been credited
        &new_decryptable_available_balance.into(), // Cipher text of the new decryptable available balance
        &token_account_authority.pubkey(),         // Token account owner
        &[&token_account_authority.pubkey()],      // Additional signers
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[apply_pending_balance_instruction],
        Some(&fee_payer_keypair.pubkey()),
        &[&token_account_authority, &fee_payer_keypair as &dyn Signer],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    print_transaction_url("Apply Pending Balance", &transaction_signature.to_string());
    Ok(())
}
