use std::error::Error;

use solana_sdk::{
    instruction::Instruction, pubkey::Pubkey, signature::Keypair, signer::Signer,
    transaction::Transaction,
};
use utils::{get_or_create_keypair, get_rpc_client, print_transaction_url};
//use solana_zk_sdk::encryption::pod::elgamal::PodElGamalCiphertext;
use spl_associated_token_account::get_associated_token_address_with_program_id;
use spl_token_2022::{
    //extension::confidential_mint_burn,
    instruction::mint_to,
    solana_zk_sdk::encryption::{
        //auth_encryption::AeKey,
        elgamal::ElGamalKeypair,
    },
};
// use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;

pub async fn go_with_confidential_mintburn(
    _mint_authority: &Keypair,
    _token_account_owner: &Pubkey,
    _mint_amount: u64,
    _supply_elgamal_pubkey: &ElGamalKeypair,
) -> Result<(), Box<dyn Error>> {
    Err("Not yet implemented".into())

    // let client = get_rpc_client()?;
    // let mint = get_or_create_keypair("mint")?;
    // let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;

    // let receiving_token_account = get_associated_token_address_with_program_id(
    //     &token_account_owner,
    //     &mint.pubkey(),
    //     &spl_token_2022::id(),
    // );

    // // Instruction to mint tokens
    // let context_state_dummy = Pubkey::new_unique();

    // let confidential_mint_instructions =
    //     confidential_mint_burn::instruction::confidential_mint_with_split_proofs(
    //         &spl_token_2022::id(),
    //         &receiving_token_account,
    //         &mint.pubkey(),
    //         Some(supply_elgamal_pubkey.pubkey_owned()),
    //         &PodElGamalCiphertext::default(),
    //         &PodElGamalCiphertext::default(),
    //         &mint_authority.pubkey(),
    //         &[&mint_authority.pubkey()],
    //         ProofLocation::ContextStateAccount(&context_state_dummy),
    //         ProofLocation::ContextStateAccount(&context_state_dummy),
    //         ProofLocation::ContextStateAccount(&context_state_dummy),
    //         AeKey::new_rand().encrypt(mint_amount).into()
    // )?;

    // let transaction = Transaction::new_signed_with_payer(
    //     confidential_mint_instructions.as_slice(),
    //     Some(&fee_payer_keypair.pubkey()),
    //     &[&fee_payer_keypair, &mint_authority],
    //     client.get_latest_blockhash()?,
    // );

    // let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    // println!(
    //     "\nMint Tokens: https://explorer.solana.com/tx/{}?cluster=custom&customUrl=http%3A%2F%2Flocalhost%3A8899",
    //     transaction_signature
    // );
    // Ok(())
}

pub async fn go(
    mint_authority: &Keypair,
    token_account_owner: &Pubkey,
    mint_amount: u64,
) -> Result<(), Box<dyn Error>> {
    let client = get_rpc_client()?;
    let mint = get_or_create_keypair("mint")?;
    let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;

    let receiving_token_account = get_associated_token_address_with_program_id(
        &token_account_owner, // Token account owner
        &mint.pubkey(),       // Mint
        &spl_token_2022::id(),
    );

    // Instruction to mint tokens
    let mint_to_instruction: Instruction = mint_to(
        &spl_token_2022::id(),
        &mint.pubkey(),              // Mint
        &receiving_token_account,    // Token account to mint to
        &mint_authority.pubkey(),    // Token account owner
        &[&mint_authority.pubkey()], // Additional signers (mint authority)
        mint_amount,                 // Amount to mint
    )?;

    let transaction = Transaction::new_signed_with_payer(
        &[mint_to_instruction],
        Some(&fee_payer_keypair.pubkey()),
        &[&fee_payer_keypair, &mint_authority],
        client.get_latest_blockhash()?,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    print_transaction_url("Mint Tokens", &transaction_signature.to_string());
    Ok(())
}
