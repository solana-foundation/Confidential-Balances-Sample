use std::error::Error;

use solana_sdk::{signer::Signer, transaction::Transaction};
use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account,
};
use spl_token_2022::{
    error::TokenError,
    extension::{
        confidential_transfer::instruction::{configure_account, PubkeyValidityProofData},
        ExtensionType,
    },
    instruction::reallocate,
    solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
};
use spl_token_confidential_transfer_proof_extraction::instruction::ProofLocation;
use utils::{get_or_create_keypair, get_rpc_client, print_transaction_url};

pub async fn setup_token_account(
    token_account_authority: &dyn Signer,
) -> Result<(), Box<dyn Error>> {
    let client = get_rpc_client()?;
    let mint = get_or_create_keypair("mint")?;
    let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;

    // Associated token address of the sender
    let token_account_pubkey = get_associated_token_address_with_program_id(
        &token_account_authority.pubkey(), // Token account owner
        &mint.pubkey(),                    // Mint
        &spl_token_2022::id(),
    );

    // Instruction to create associated token account
    let create_associated_token_account_instruction = create_associated_token_account(
        &fee_payer_keypair.pubkey(),       // Funding account
        &token_account_authority.pubkey(), // Token account owner
        &mint.pubkey(),                    // Mint
        &spl_token_2022::id(),
    );

    // Instruction to reallocate the token account to include the `ConfidentialTransferAccount` extension
    let reallocate_instruction = reallocate(
        &spl_token_2022::id(),
        &token_account_pubkey,                         // Token account
        &fee_payer_keypair.pubkey(),                   // Payer
        &token_account_authority.pubkey(),             // Token account owner
        &[&token_account_authority.pubkey()],          // Signers
        &[ExtensionType::ConfidentialTransferAccount], // Extension to reallocate space for
    )?;

    // Create the ElGamal keypair and AES key for the sender token account
    let token_account_authority_elgamal_keypair =
        ElGamalKeypair::new_from_signer(&token_account_authority, &token_account_pubkey.to_bytes())
            .unwrap();
    let token_account_authority_aes_key =
        AeKey::new_from_signer(&token_account_authority, &token_account_pubkey.to_bytes()).unwrap();

    // The maximum number of `Deposit` and `Transfer` instructions that can
    // credit `pending_balance` before the `ApplyPendingBalance` instruction is executed
    let maximum_pending_balance_credit_counter = 65536;

    // Initial token balance is 0
    let decryptable_balance = token_account_authority_aes_key.encrypt(0);

    // The instruction data that is needed for the `ProofInstruction::VerifyPubkeyValidity` instruction.
    // It includes the cryptographic proof as well as the context data information needed to verify the proof.
    // Generating the proof data client-side (instead of using a separate proof account)
    let proof_data = PubkeyValidityProofData::new(&token_account_authority_elgamal_keypair)
        .map_err(|_| TokenError::ProofGeneration)?;

    // `InstructionOffset` indicates that proof is included in the same transaction
    // This means that the proof instruction offset must be always be 1.
    let proof_location = ProofLocation::InstructionOffset(1.try_into().unwrap(), &proof_data);

    // Instructions to configure the token account, including the proof instruction
    // Appends the `VerifyPubkeyValidityProof` instruction right after the `ConfigureAccount` instruction.
    let configure_account_instruction = configure_account(
        &spl_token_2022::id(),                  // Program ID
        &token_account_pubkey,                  // Token account
        &mint.pubkey(),                         // Mint
        &decryptable_balance.into(),            // Initial balance
        maximum_pending_balance_credit_counter, // Maximum pending balance credit counter
        &token_account_authority.pubkey(),      // Token Account Owner
        &[],                                    // Additional signers
        proof_location,                         // Proof location
    )
    .unwrap();

    // Instructions to configure account must come after `initialize_account` instruction
    let mut instructions = vec![
        create_associated_token_account_instruction,
        reallocate_instruction,
    ];
    instructions.extend(configure_account_instruction);

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&fee_payer_keypair.pubkey()),
        &[&token_account_authority, &fee_payer_keypair as &dyn Signer],
        recent_blockhash,
    );

    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    print_transaction_url("Create Token Account", &transaction_signature.to_string());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::get_or_create_keypair;
    #[tokio::test]
    async fn test_setup_token_account() -> Result<(), Box<dyn Error>> {
        let sender_keypair = get_or_create_keypair("sender_keypair")?;

        setup_token_account(&sender_keypair).await?;
        Ok(())
    }
}
