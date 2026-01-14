use {
    serde_json::json,
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signature, Signer},
        transaction::Transaction,
    },
    solana_system_interface::instruction as system_instruction,
    spl_associated_token_account::get_associated_token_address_with_program_id,
    spl_token_2022::{
        extension::{
            confidential_transfer::{
                account_info::TransferAccountInfo, ConfidentialTransferAccount,
                ConfidentialTransferMint,
            },
            BaseStateWithExtensions, StateWithExtensionsOwned,
        },
        solana_zk_sdk::{
            encryption::{
                auth_encryption::AeKey,
                elgamal::{self, ElGamalKeypair},
                pod::elgamal::PodElGamalPubkey,
            },
            zk_elgamal_proof_program::{
                self,
                instruction::{close_context_state, ContextStateInfo},
            },
        },
        state::{Account, Mint},
    },
    spl_token_client::{
        client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
        token::{ProofAccountWithCiphertext, Token},
    },
    spl_token_confidential_transfer_proof_generation::transfer::TransferProofData,
    std::{error::Error, sync::Arc},
    utils::{
        get_non_blocking_rpc_client, get_or_create_keypair, get_rpc_client, jito, load_value,
        print_transaction_url, record_value,
    },
};

struct TransferContext {
    equality_proof_pubkey: Pubkey,
    ciphertext_validity_proof_pubkey: Pubkey,
    range_proof_pubkey: Pubkey,
    ciphertext_validity_proof_account_with_ciphertext: ProofAccountWithCiphertext,
    sender_associated_token_address: Pubkey,
    recipient_associated_token_address: Pubkey,
    sender_transfer_account_info: TransferAccountInfo,
    sender_elgamal_keypair: ElGamalKeypair,
    sender_aes_key: AeKey,
    recipient_elgamal_pubkey: elgamal::ElGamalPubkey,
    auditor_elgamal_pubkey: elgamal::ElGamalPubkey,
}

pub async fn with_split_proofs(
    sender_keypair: Arc<dyn Signer>,
    recipient_keypair: Arc<dyn Signer>,
    confidential_transfer_amount: u64,
) -> Result<(), Box<dyn Error>> {
    let client = get_rpc_client()?;
    let (transactions, ctx) = prepare_proof_transactions(
        sender_keypair.clone(),
        recipient_keypair,
        confidential_transfer_amount,
    )
    .await?;

    print_transaction_url(
        "Transfer [Allocate Proof Accounts]",
        &client
            .send_and_confirm_transaction(&transactions[0])?
            .to_string(),
    );
    print_transaction_url(
        "Transfer [Encode Range Proof]",
        &client
            .send_and_confirm_transaction(&transactions[1])?
            .to_string(),
    );
    print_transaction_url(
        "Transfer [Encode Remaining Proofs]",
        &client
            .send_and_confirm_transaction(&transactions[2])?
            .to_string(),
    );

    let transfer_signature =
        execute_transfer(sender_keypair.clone(), &ctx, confidential_transfer_amount).await?;
    print_transaction_url(
        "Transfer [Execute Transfer]",
        &transfer_signature.to_string(),
    );

    let close_tx = build_close_proof_accounts_tx(sender_keypair.clone(), &ctx, &client)?;
    print_transaction_url(
        "Transfer [Close Proof Accounts]",
        &client.send_and_confirm_transaction(&close_tx)?.to_string(),
    );

    record_value(
        "last_confidential_transfer_signature",
        &transfer_signature.to_string(),
    )?;

    Ok(())
}

async fn execute_transfer(
    sender_keypair: Arc<dyn Signer>,
    ctx: &TransferContext,
    confidential_transfer_amount: u64,
) -> Result<Signature, Box<dyn Error>> {
    let mint = get_or_create_keypair("mint")?;
    let decimals = load_value("mint_decimals")?;

    let token = {
        let rpc_client = get_non_blocking_rpc_client()?;
        let program_client: ProgramRpcClient<ProgramRpcClientSendTransaction> =
            ProgramRpcClient::new(Arc::new(rpc_client), ProgramRpcClientSendTransaction);
        Token::new(
            Arc::new(program_client),
            &spl_token_2022::id(),
            &mint.pubkey(),
            Some(decimals),
            sender_keypair.clone(),
        )
    };

    let response = token
        .confidential_transfer_transfer(
            &ctx.sender_associated_token_address,
            &ctx.recipient_associated_token_address,
            &sender_keypair.pubkey(),
            Some(&ctx.equality_proof_pubkey),
            Some(&ctx.ciphertext_validity_proof_account_with_ciphertext),
            Some(&ctx.range_proof_pubkey),
            confidential_transfer_amount,
            Some(ctx.sender_transfer_account_info.clone()),
            &ctx.sender_elgamal_keypair,
            &ctx.sender_aes_key,
            &ctx.recipient_elgamal_pubkey,
            Some(&ctx.auditor_elgamal_pubkey),
            &[&sender_keypair],
        )
        .await?;

    match response {
        spl_token_client::client::RpcClientResponse::Signature(sig) => Ok(sig),
        _ => Err("Expected signature response from transfer".into()),
    }
}

fn build_close_proof_accounts_tx(
    sender_keypair: Arc<dyn Signer>,
    ctx: &TransferContext,
    client: &solana_client::rpc_client::RpcClient,
) -> Result<Transaction, Box<dyn Error>> {
    let context_state_authority_pubkey = sender_keypair.pubkey();
    let destination_account = &sender_keypair.pubkey();

    let close_equality_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &ctx.equality_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &destination_account,
    );

    let close_ciphertext_validity_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &ctx.ciphertext_validity_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &destination_account,
    );

    let close_range_proof_instruction = close_context_state(
        ContextStateInfo {
            context_state_account: &ctx.range_proof_pubkey,
            context_state_authority: &context_state_authority_pubkey,
        },
        &destination_account,
    );

    let recent_blockhash = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[
            close_equality_proof_instruction,
            close_ciphertext_validity_proof_instruction,
            close_range_proof_instruction,
        ],
        Some(&sender_keypair.pubkey()),
        &[&sender_keypair],
        recent_blockhash,
    );

    Ok(tx)
}

async fn prepare_proof_transactions(
    sender_keypair: Arc<dyn Signer>,
    recipient_keypair: Arc<dyn Signer>,
    confidential_transfer_amount: u64,
) -> Result<(Vec<Transaction>, TransferContext), Box<dyn Error>> {
    let client = get_rpc_client()?;

    let mint = get_or_create_keypair("mint")?;
    let sender_associated_token_address: Pubkey = get_associated_token_address_with_program_id(
        &sender_keypair.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );
    let decimals = load_value("mint_decimals")?;

    let token = {
        let rpc_client = get_non_blocking_rpc_client()?;

        let program_client: ProgramRpcClient<ProgramRpcClientSendTransaction> =
            ProgramRpcClient::new(Arc::new(rpc_client), ProgramRpcClientSendTransaction);

        Token::new(
            Arc::new(program_client),
            &spl_token_2022::id(),
            &mint.pubkey(),
            Some(decimals),
            sender_keypair.clone(),
        )
    };
    let recipient_associated_token_address = get_associated_token_address_with_program_id(
        &recipient_keypair.pubkey(),
        &mint.pubkey(),
        &spl_token_2022::id(),
    );

    let context_state_authority = &sender_keypair;

    let equality_proof_context_state_account = Keypair::new();
    let equality_proof_pubkey = equality_proof_context_state_account.pubkey();

    let ciphertext_validity_proof_context_state_account = Keypair::new();
    let ciphertext_validity_proof_pubkey = ciphertext_validity_proof_context_state_account.pubkey();

    let range_proof_context_state_account = Keypair::new();
    let range_proof_pubkey = range_proof_context_state_account.pubkey();

    let sender_token_account_info = token
        .get_account_info(&sender_associated_token_address)
        .await?;

    let sender_account_extension_data =
        sender_token_account_info.get_extension::<ConfidentialTransferAccount>()?;

    let sender_transfer_account_info = TransferAccountInfo::new(sender_account_extension_data);

    let sender_elgamal_keypair = ElGamalKeypair::new_from_signer(
        &sender_keypair,
        &sender_associated_token_address.to_bytes(),
    )?;
    let sender_aes_key =
        AeKey::new_from_signer(&sender_keypair, &sender_associated_token_address.to_bytes())?;

    let recipient_account = token
        .get_account(recipient_associated_token_address)
        .await?;

    let recipient_elgamal_pubkey: elgamal::ElGamalPubkey =
        StateWithExtensionsOwned::<Account>::unpack(recipient_account.data)?
            .get_extension::<ConfidentialTransferAccount>()?
            .elgamal_pubkey
            .try_into()?;

    let mint_account = token.get_account(mint.pubkey()).await?;

    let auditor_elgamal_pubkey_option = Option::<PodElGamalPubkey>::from(
        StateWithExtensionsOwned::<Mint>::unpack(mint_account.data)?
            .get_extension::<ConfidentialTransferMint>()?
            .auditor_elgamal_pubkey,
    );

    let auditor_elgamal_pubkey: elgamal::ElGamalPubkey = auditor_elgamal_pubkey_option
        .ok_or("No Auditor ElGamal pubkey")?
        .try_into()?;

    let TransferProofData {
        equality_proof_data,
        ciphertext_validity_proof_data_with_ciphertext,
        range_proof_data,
    } = sender_transfer_account_info.generate_split_transfer_proof_data(
        confidential_transfer_amount,
        &sender_elgamal_keypair,
        &sender_aes_key,
        &recipient_elgamal_pubkey,
        Some(&auditor_elgamal_pubkey),
    )?;

    let (range_create_ix, range_verify_ix) =
        get_zk_proof_context_state_account_creation_instructions(
            &sender_keypair.pubkey(),
            &range_proof_context_state_account.pubkey(),
            &context_state_authority.pubkey(),
            &range_proof_data,
        )?;

    let (equality_create_ix, equality_verify_ix) =
        get_zk_proof_context_state_account_creation_instructions(
            &sender_keypair.pubkey(),
            &equality_proof_context_state_account.pubkey(),
            &context_state_authority.pubkey(),
            &equality_proof_data,
        )?;

    let (cv_create_ix, cv_verify_ix) = get_zk_proof_context_state_account_creation_instructions(
        &sender_keypair.pubkey(),
        &ciphertext_validity_proof_context_state_account.pubkey(),
        &context_state_authority.pubkey(),
        &ciphertext_validity_proof_data_with_ciphertext.proof_data,
    )?;

    let tx1 = Transaction::new_signed_with_payer(
        &[
            range_create_ix.clone(),
            equality_create_ix.clone(),
            cv_create_ix.clone(),
        ],
        Some(&sender_keypair.pubkey()),
        &[
            &sender_keypair,
            &range_proof_context_state_account as &dyn Signer,
            &equality_proof_context_state_account as &dyn Signer,
            &ciphertext_validity_proof_context_state_account as &dyn Signer,
        ],
        client.get_latest_blockhash()?,
    );

    let tx2 = Transaction::new_signed_with_payer(
        &[range_verify_ix],
        Some(&sender_keypair.pubkey()),
        &[&sender_keypair],
        client.get_latest_blockhash()?,
    );

    let tx3 = Transaction::new_signed_with_payer(
        &[equality_verify_ix, cv_verify_ix],
        Some(&sender_keypair.pubkey()),
        &[&sender_keypair],
        client.get_latest_blockhash()?,
    );

    let ciphertext_validity_proof_account_with_ciphertext = ProofAccountWithCiphertext {
        context_state_account: ciphertext_validity_proof_pubkey,
        ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
    };

    let ctx = TransferContext {
        equality_proof_pubkey,
        ciphertext_validity_proof_pubkey,
        range_proof_pubkey,
        ciphertext_validity_proof_account_with_ciphertext,
        sender_associated_token_address,
        recipient_associated_token_address,
        sender_transfer_account_info,
        sender_elgamal_keypair,
        sender_aes_key,
        recipient_elgamal_pubkey,
        auditor_elgamal_pubkey,
    };

    Ok((vec![tx1, tx2, tx3], ctx))
}

pub async fn with_split_proofs_atomic(
    sender_keypair: Arc<dyn Signer>,
    recipient_keypair: Arc<dyn Signer>,
    confidential_transfer_amount: u64,
) -> Result<(), Box<dyn Error>> {
    utils::run_with_retry(5, || async {
        let client = get_rpc_client()?;
        let (mut transactions, ctx) = prepare_proof_transactions(
            sender_keypair.clone(),
            recipient_keypair.clone(),
            confidential_transfer_amount,
        )
        .await?;

        assert!(
            client.url().contains("testnet") || client.url().contains("mainnet"),
            "This Jito demo only works on testnet or mainnet (adjust code for custom endpoints)"
        );

        let jito_tip_ix = jito::create_jito_tip_instruction(sender_keypair.pubkey()).await?;

        let tx3 = &mut transactions[2];
        {
            let mut unique_pubkeys: std::collections::HashSet<_> =
                tx3.message.account_keys.iter().cloned().collect();
            tx3.message.account_keys.extend(
                jito_tip_ix
                    .accounts
                    .iter()
                    .map(|account| account.pubkey)
                    .filter(|pubkey| unique_pubkeys.insert(*pubkey)),
            );

            tx3.message
                .account_keys
                .push(solana_system_interface::program::id());
        }

        let compiled_jito_tip_ix = tx3.message.compile_instruction(&jito_tip_ix);
        tx3.message.instructions.push(compiled_jito_tip_ix);
        tx3.sign(&[&sender_keypair], client.get_latest_blockhash()?);

        let transfer_signature =
            execute_transfer(sender_keypair.clone(), &ctx, confidential_transfer_amount).await?;

        let close_tx = build_close_proof_accounts_tx(sender_keypair.clone(), &ctx, &client)?;

        let serialized_tx1 = bs58::encode(bincode::serialize(&transactions[0])?).into_string();
        let serialized_tx2 = bs58::encode(bincode::serialize(&transactions[1])?).into_string();
        let serialized_tx3 = bs58::encode(bincode::serialize(&transactions[2])?).into_string();
        let serialized_tx4 = bs58::encode(transfer_signature.as_ref()).into_string();
        let serialized_tx5 = bs58::encode(bincode::serialize(&close_tx)?).into_string();

        let tx_bundle = json!([
            serialized_tx1,
            serialized_tx2,
            serialized_tx3,
            serialized_tx4,
            serialized_tx5
        ]);

        let bundled_signatures = jito::submit_and_confirm_bundle(tx_bundle).await?;
        print_transaction_url("Transfer [Allocate Proof Accounts]", &bundled_signatures[0]);
        print_transaction_url("Transfer [Encode Range Proof]", &bundled_signatures[1]);
        print_transaction_url("Transfer [Encode Remaining Proofs]", &bundled_signatures[2]);
        print_transaction_url("Transfer [Execute Transfer]", &bundled_signatures[3]);
        print_transaction_url("Transfer [Close Proof Accounts]", &bundled_signatures[4]);

        record_value(
            "last_confidential_transfer_signature",
            &bundled_signatures[3],
        )?;

        Ok(())
    })
    .await
}

fn get_zk_proof_context_state_account_creation_instructions<
    ZK: bytemuck::Pod + zk_elgamal_proof_program::proof_data::ZkProofData<U>,
    U: bytemuck::Pod,
>(
    fee_payer_pubkey: &Pubkey,
    context_state_account_pubkey: &Pubkey,
    context_state_authority_pubkey: &Pubkey,
    proof_data: &ZK,
) -> Result<
    (
        solana_sdk::instruction::Instruction,
        solana_sdk::instruction::Instruction,
    ),
    Box<dyn Error>,
> {
    use spl_token_confidential_transfer_proof_extraction::instruction::zk_proof_type_to_instruction;
    use std::mem::size_of;

    let client = get_rpc_client()?;
    let space = size_of::<zk_elgamal_proof_program::state::ProofContextState<U>>();
    let rent = client.get_minimum_balance_for_rent_exemption(space)?;

    let context_state_info = ContextStateInfo {
        context_state_account: context_state_account_pubkey,
        context_state_authority: context_state_authority_pubkey,
    };

    let instruction_type = zk_proof_type_to_instruction(ZK::PROOF_TYPE)?;

    let create_account_ix = system_instruction::create_account(
        fee_payer_pubkey,
        context_state_account_pubkey,
        rent,
        space as u64,
        &zk_elgamal_proof_program::id(),
    );

    let verify_proof_ix =
        instruction_type.encode_verify_proof(Some(context_state_info), proof_data);

    Ok((create_account_ix, verify_proof_ix))
}
