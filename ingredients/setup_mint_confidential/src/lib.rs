use {
    solana_sdk::{signature::Keypair, signer::Signer, transaction::Transaction},
    solana_system_interface::instruction::create_account,
    spl_token_2022::{
        extension::{confidential_mint_burn, ExtensionType},
        instruction::initialize_mint,
        solana_zk_sdk::encryption::{
            auth_encryption::AeKey, elgamal::ElGamalKeypair, pod::elgamal::PodElGamalPubkey,
        },
        state::Mint,
    },
    spl_token_client::token::ExtensionInitializationParams,
    std::{error::Error, sync::Arc},
    utils::{get_or_create_keypair, get_rpc_client, record_value},
};

pub async fn create_mint(
    absolute_authority: &Keypair,
    auditor_elgamal_keypair: &ElGamalKeypair,
) -> Result<(), Box<dyn Error>> {
    let fee_payer_keypair = Arc::new(get_or_create_keypair("fee_payer_keypair")?);
    let client = get_rpc_client()?;
    let mint = get_or_create_keypair("mint")?;
    let mint_authority = absolute_authority;
    let freeze_authority = absolute_authority;
    let decimals = record_value("mint_decimals", 2)?;

    // Confidential Transfer Extension authority
    // Authority to modify the `ConfidentialTransferMint` configuration and to approve new accounts (if `auto_approve_new_accounts` is false?)
    let authority = absolute_authority;

    // Calculate the space required for the mint account with the extension
    let space = ExtensionType::try_calculate_account_len::<Mint>(&[
        ExtensionType::ConfidentialTransferMint,
        ExtensionType::ConfidentialMintBurn,
    ])?;

    // Calculate the lamports required for the mint account
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    // Instructions to create the mint account
    let create_account_instruction = create_account(
        &fee_payer_keypair.pubkey(),
        &mint.pubkey(),
        rent,
        space as u64,
        &spl_token_2022::id(),
    );

    // ConfidentialTransferMint extension instruction
    let extension_confidential_transfer_init_instruction =
        ExtensionInitializationParams::ConfidentialTransferMint {
            authority: Some(authority.pubkey()),
            auto_approve_new_accounts: true, // If `true`, no approval is required and new accounts may be used immediately
            auditor_elgamal_pubkey: Some((*auditor_elgamal_keypair.pubkey()).into()),
        }
        .instruction(&spl_token_2022::id(), &mint.pubkey())?;

    let pod_auditor_elgamal_keypair: PodElGamalPubkey =
        auditor_elgamal_keypair.pubkey_owned().into();
    let extension_mintburn_init_instruction = confidential_mint_burn::instruction::initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &pod_auditor_elgamal_keypair,
        &AeKey::new_rand().encrypt(0).into(),
    )?;

    // Initialize the mint account
    //TODO: Use program-2022/src/extension/confidential_transfer/instruction/initialize_mint()
    let initialize_mint_instruction = initialize_mint(
        &spl_token_2022::id(),
        &mint.pubkey(),
        &mint_authority.pubkey(),
        Some(&freeze_authority.pubkey()),
        decimals,
    )?;

    let instructions = vec![
        create_account_instruction,
        extension_confidential_transfer_init_instruction,
        extension_mintburn_init_instruction,
        initialize_mint_instruction,
    ];

    let recent_blockhash = client.get_latest_blockhash()?;
    let transaction = Transaction::new_signed_with_payer(
        &instructions,
        Some(&fee_payer_keypair.pubkey()),
        &[&fee_payer_keypair, &mint as &dyn Signer],
        recent_blockhash,
    );
    let transaction_signature = client.send_and_confirm_transaction(&transaction)?;

    println!(
        "\nCreate Mint Account: https://explorer.solana.com/tx/{}?cluster=custom&customUrl=http%3A%2F%2Flocalhost%3A8899",
        transaction_signature
    );

    Ok(())
}
