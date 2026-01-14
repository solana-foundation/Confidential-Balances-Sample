use {
    solana_sdk::signature::{Keypair, Signer},
    spl_associated_token_account::get_associated_token_address_with_program_id,
    spl_token_2022::{
        extension::{
            confidential_transfer::{
                account_info::WithdrawAccountInfo, ConfidentialTransferAccount,
            },
            BaseStateWithExtensions,
        },
        solana_zk_sdk::encryption::{auth_encryption::AeKey, elgamal::ElGamalKeypair},
    },
    spl_token_client::{
        client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
        token::Token,
    },
    spl_token_confidential_transfer_proof_generation::withdraw::WithdrawProofData,
    std::{error::Error, sync::Arc},
    utils::{
        get_non_blocking_rpc_client, get_or_create_keypair, load_value, print_transaction_url,
    },
};

pub async fn withdraw_tokens(
    withdraw_amount: u64,
    recipient_signer: Arc<dyn Signer>,
) -> Result<(), Box<dyn Error>> {
    let mint = get_or_create_keypair("mint")?;
    let decimals = load_value("mint_decimals")?;
    let recipient_associated_token_address = get_associated_token_address_with_program_id(
        &recipient_signer.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

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
            recipient_signer.clone(),
            // ^^^ HACK: Unsafe clone of keypair due to Rust lifetime issues.
        )
    };

    let receiver_elgamal_keypair = ElGamalKeypair::new_from_signer(
        &recipient_signer,
        &recipient_associated_token_address.to_bytes(),
    )
    .unwrap();
    let receiver_aes_key = AeKey::new_from_signer(
        &recipient_signer,
        &recipient_associated_token_address.to_bytes(),
    )
    .unwrap();

    // Get recipient token account data
    let token_account = token
        .get_account_info(&recipient_associated_token_address)
        .await?;

    // Unpack the ConfidentialTransferAccount extension portion of the token account data
    let extension_data = token_account.get_extension::<ConfidentialTransferAccount>()?;

    // Confidential Transfer extension information needed to construct a `Withdraw` instruction.
    let withdraw_account_info = WithdrawAccountInfo::new(extension_data);

    // Authority for the withdraw proof account (to close the account)
    let context_state_authority = &recipient_signer;

    let equality_proof_context_state_keypair = Keypair::new();
    let equality_proof_context_state_pubkey = equality_proof_context_state_keypair.pubkey();
    let range_proof_context_state_keypair = Keypair::new();
    let range_proof_context_state_pubkey = range_proof_context_state_keypair.pubkey();

    // Create a withdraw proof data
    let WithdrawProofData {
        equality_proof_data,
        range_proof_data,
    } = withdraw_account_info.generate_proof_data(
        withdraw_amount,
        &receiver_elgamal_keypair,
        &receiver_aes_key,
    )?;

    // Generate withdrawal proof accounts
    let context_state_authority_pubkey = context_state_authority.pubkey();
    let create_equality_proof_signer = &[&equality_proof_context_state_keypair];
    let create_range_proof_signer = &[&range_proof_context_state_keypair];

    let equality_sig = token
        .confidential_transfer_create_context_state_account(
            &equality_proof_context_state_pubkey,
            &context_state_authority_pubkey,
            &equality_proof_data,
            false,
            create_equality_proof_signer,
        )
        .await?;
    print_transaction_url(
        "Equality Proof Context State Account",
        &equality_sig.to_string(),
    );

    let range_sig = token
        .confidential_transfer_create_context_state_account(
            &range_proof_context_state_pubkey,
            &context_state_authority_pubkey,
            &range_proof_data,
            true,
            create_range_proof_signer,
        )
        .await?;
    print_transaction_url("Range Proof Context State Account", &range_sig.to_string());

    let withdraw_sig = token
        .confidential_transfer_withdraw(
            &recipient_associated_token_address,
            &recipient_signer.pubkey(),
            Some(&equality_proof_context_state_pubkey),
            Some(&range_proof_context_state_pubkey),
            withdraw_amount,
            decimals,
            Some(withdraw_account_info),
            &receiver_elgamal_keypair,
            &receiver_aes_key,
            &[&recipient_signer],
        )
        .await?;
    print_transaction_url("Withdraw Transaction", &withdraw_sig.to_string());

    let close_context_state_signer = &[&context_state_authority];

    let close_equality_sig = token
        .confidential_transfer_close_context_state_account(
            &equality_proof_context_state_pubkey,
            &recipient_associated_token_address,
            &context_state_authority_pubkey,
            close_context_state_signer,
        )
        .await?;
    print_transaction_url(
        "Close Equality Proof Context State Account",
        &close_equality_sig.to_string(),
    );

    let close_range_sig = token
        .confidential_transfer_close_context_state_account(
            &range_proof_context_state_pubkey,
            &recipient_associated_token_address,
            &context_state_authority_pubkey,
            close_context_state_signer,
        )
        .await?;
    print_transaction_url(
        "Close Range Proof Context State Account",
        &close_range_sig.to_string(),
    );

    Ok(())
}
