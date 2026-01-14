use std::error::Error;

use solana_sdk::{signer::Signer, transaction::Transaction};
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::extension::confidential_transfer::instruction::deposit;
use utils::{get_or_create_keypair, get_rpc_client, load_value, print_transaction_url};

pub async fn deposit_tokens(
    deposit_amount: u64,
    depositor_signer: &dyn Signer,
) -> Result<(), Box<dyn Error>> {
    let client = get_rpc_client()?;
    let mint = get_or_create_keypair("mint")?;
    let decimals = load_value("mint_decimals")?;

    // Confidential balance has separate "pending" and "available" balances
    // Must first deposit tokens from non-confidential balance to  "pending" confidential balance

    let depositor_token_account = get_associated_token_address_with_program_id(
        &depositor_signer.pubkey(), // Token account owner
        &mint.pubkey(),             // Mint
        &spl_token_2022::id(),
    );

    // Instruction to deposit from non-confidential balance to "pending" balance
    let deposit_instruction = deposit(
        &spl_token_2022::id(),
        &depositor_token_account,      // Token account
        &mint.pubkey(),                // Mint
        deposit_amount,                // Amount to deposit
        decimals,                      // Mint decimals
        &depositor_signer.pubkey(),    // Token account owner
        &[&depositor_signer.pubkey()], // Signers
    )?;

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &[deposit_instruction],
        Some(&depositor_signer.pubkey()),
        &[&depositor_signer],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    print_transaction_url("Deposit Tokens", &transaction_signature.to_string());
    Ok(())
}
