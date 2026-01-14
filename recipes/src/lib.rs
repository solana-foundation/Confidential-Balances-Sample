#[cfg(test)]
mod recipe {
    use std::error::Error;
    use std::sync::Arc;

    use apply_pending_balance;
    use deposit_tokens;
    use mint_tokens;
    use setup_mint;
    use setup_mint_confidential;
    use setup_participants;
    use setup_token_account;
    use solana_sdk::{native_token::LAMPORTS_PER_SOL, signer::Signer};
    use transfer;
    use utils::{get_or_create_keypair, get_or_create_keypair_elgamal};
    use withdraw_tokens;

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn confidential_mintburn_transfer_recipe() -> Result<(), Box<dyn Error>> {
        let sender_keypair = get_or_create_keypair("sender_keypair")?;
        let recipient_keypair = get_or_create_keypair("recipient_keypair")?;
        let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;
        let auditor_elgamal_keypair = get_or_create_keypair_elgamal("auditor_elgamal")?;
        let absolute_mint_authority = get_or_create_keypair("absolute_mint_authority")?;

        // Step 1. Setup participants
        setup_participants::setup_basic_participant(
            &fee_payer_keypair.pubkey(),
            None,
            2 * LAMPORTS_PER_SOL,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &sender_keypair.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &recipient_keypair.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 5,
        )
        .await?;

        // Step 2. Create mint
        setup_mint_confidential::create_mint(&absolute_mint_authority, &auditor_elgamal_keypair)
            .await?;

        // Step 3. Setup token account for sender
        setup_token_account::setup_token_account(&sender_keypair).await?;

        // Step 4. Confidentially mint tokens
        mint_tokens::go_with_confidential_mintburn(
            &absolute_mint_authority,
            &sender_keypair.pubkey(),
            100_00,
            &auditor_elgamal_keypair,
        )
        .await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn basic_transfer_recipe() -> Result<(), Box<dyn Error>> {
        let sender_keypair = Arc::new(get_or_create_keypair("sender_keypair")?);
        let recipient_keypair = Arc::new(get_or_create_keypair("recipient_keypair")?);
        let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;
        let auditor_elgamal_keypair = get_or_create_keypair_elgamal("auditor_elgamal")?;
        let absolute_mint_authority = get_or_create_keypair("absolute_mint_authority")?;

        // Step 1. Setup participants
        setup_participants::setup_basic_participant(
            &fee_payer_keypair.pubkey(),
            None,
            2 * LAMPORTS_PER_SOL,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &sender_keypair.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 2,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &recipient_keypair.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 5,
        )
        .await?;

        // Step 2. Create mint
        setup_mint::create_mint(&absolute_mint_authority, &auditor_elgamal_keypair).await?;

        // Step 3. Setup token account for sender
        setup_token_account::setup_token_account(&sender_keypair).await?;

        // Step 4. Mint tokens
        mint_tokens::go(&absolute_mint_authority, &sender_keypair.pubkey(), 100_00).await?;

        // Step 5. Deposit tokens
        deposit_tokens::deposit_tokens(50_00, &sender_keypair).await?;

        // Step 6. Apply pending balance
        apply_pending_balance::apply_pending_balance(&sender_keypair).await?;

        // Step 7. Create recipient token account
        setup_token_account::setup_token_account(&recipient_keypair).await?;

        // Step 8. Transfer tokens with split proofs
        transfer::with_split_proofs(sender_keypair.clone(), recipient_keypair.clone(), 50_00)
            .await?;

        // Step 9. Apply recipient's pending balance
        apply_pending_balance::apply_pending_balance(&recipient_keypair).await?;

        // Step 10. Withdraw tokens
        withdraw_tokens::withdraw_tokens(20_00, recipient_keypair.clone()).await?;

        // Step 11. Auditor asserts last transfer amount
        global_auditor_assert::last_transfer_amount(50_00, &auditor_elgamal_keypair).await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn basic_transfer_recipe_atomic() -> Result<(), Box<dyn Error>> {
        let sender_keypair = Arc::new(get_or_create_keypair("sender_keypair")?);
        let recipient_keypair = Arc::new(get_or_create_keypair("recipient_keypair")?);
        let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;
        let auditor_elgamal_keypair = get_or_create_keypair_elgamal("auditor_elgamal")?;
        let absolute_mint_authority = get_or_create_keypair("absolute_mint_authority")?;

        // Step 1. Setup participants
        setup_participants::setup_basic_participant(
            &fee_payer_keypair.pubkey(),
            None,
            2 * LAMPORTS_PER_SOL,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &sender_keypair.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 2,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &recipient_keypair.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 5,
        )
        .await?;

        // Step 2. Create mint
        setup_mint::create_mint(&absolute_mint_authority, &auditor_elgamal_keypair).await?;

        // Step 3. Setup token account for sender
        setup_token_account::setup_token_account(&sender_keypair).await?;

        // Step 4. Mint tokens
        mint_tokens::go(&absolute_mint_authority, &sender_keypair.pubkey(), 100_00).await?;

        // Step 5. Deposit tokens
        deposit_tokens::deposit_tokens(50_00, &sender_keypair).await?;

        // Step 6. Apply pending balance
        apply_pending_balance::apply_pending_balance(&sender_keypair).await?;

        // Step 7. Create recipient token account
        setup_token_account::setup_token_account(&recipient_keypair).await?;

        // Step 8. Transfer tokens with split proofs
        transfer::with_split_proofs_atomic(
            sender_keypair.clone(),
            recipient_keypair.clone(),
            50_00,
        )
        .await?;

        // Step 9. Apply recipient's pending balance
        apply_pending_balance::apply_pending_balance(&recipient_keypair).await?;

        // Step 10. Withdraw tokens
        withdraw_tokens::withdraw_tokens(20_00, recipient_keypair.clone()).await?;

        // Step 11. Auditor asserts last transfer amount
        global_auditor_assert::last_transfer_amount(50_00, &auditor_elgamal_keypair).await?;

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn basic_transfer_recipe_gcp() -> Result<(), Box<dyn Error>> {
        let sender_signer = utils::get_gcp_signer_from_env("projects/cookbook-448105/locations/us-west1/keyRings/test/cryptoKeys/first_key/cryptoKeyVersions/1").await?;
        let recipient_signer = utils::get_gcp_signer_from_env("projects/cookbook-448105/locations/us-west1/keyRings/test/cryptoKeys/second_key/cryptoKeyVersions/1").await?;

        let recipient_signer = Arc::new(recipient_signer);
        let sender_signer = Arc::new(sender_signer);

        let fee_payer_keypair = get_or_create_keypair("fee_payer_keypair")?;
        let auditor_elgamal_keypair = get_or_create_keypair_elgamal("auditor_elgamal")?;
        let absolute_mint_authority = get_or_create_keypair("absolute_mint_authority")?;

        // Step 1. Setup participants
        setup_participants::setup_basic_participant(
            &fee_payer_keypair.pubkey(),
            None,
            2 * LAMPORTS_PER_SOL,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &sender_signer.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 2,
        )
        .await?;
        setup_participants::setup_basic_participant(
            &recipient_signer.pubkey(),
            Some(&fee_payer_keypair),
            LAMPORTS_PER_SOL / 5,
        )
        .await?;

        // Step 2. Create mint
        setup_mint::create_mint(&absolute_mint_authority, &auditor_elgamal_keypair).await?;

        // Step 3. Setup token account for sender
        setup_token_account::setup_token_account(&sender_signer).await?;

        // Step 4. Mint tokens
        mint_tokens::go(&absolute_mint_authority, &sender_signer.pubkey(), 100_00).await?;

        // Step 5. Deposit tokens
        deposit_tokens::deposit_tokens(50_00, &sender_signer).await?;

        // Step 6. Apply pending balance
        apply_pending_balance::apply_pending_balance(&sender_signer).await?;

        // Step 7. Create recipient token account
        setup_token_account::setup_token_account(&recipient_signer).await?;

        // Step 8. Transfer tokens with split proofs
        transfer::with_split_proofs(sender_signer.clone(), recipient_signer.clone(), 50_00).await?;

        // Step 9. Apply recipient's pending balance
        apply_pending_balance::apply_pending_balance(&recipient_signer).await?;

        // Step 10. Withdraw tokens
        withdraw_tokens::withdraw_tokens(20_00, recipient_signer.clone()).await?;

        // Step 11. Auditor asserts last transfer amount
        global_auditor_assert::last_transfer_amount(50_00, &auditor_elgamal_keypair).await?;

        Ok(())
    }
}
