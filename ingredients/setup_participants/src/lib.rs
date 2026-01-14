use utils::get_rpc_client;
use {
    solana_sdk::{pubkey::Pubkey, signature::Keypair, signer::Signer, transaction::Transaction},
    solana_system_interface::instruction as system_instruction,
    std::error::Error,
};

pub async fn setup_basic_participant(
    participant_pubkey: &Pubkey,
    fee_payer_keypair: Option<&Keypair>,
    initial_lamports: u64,
) -> Result<(), Box<dyn Error>> {
    let client = get_rpc_client()?;

    match fee_payer_keypair {
        Some(keypair) => {
            let recent_blockhash = client.get_latest_blockhash()?;
            let ix = system_instruction::transfer(
                &keypair.pubkey(),
                participant_pubkey,
                initial_lamports,
            );
            let tx = Transaction::new_signed_with_payer(
                &[ix],
                Some(&keypair.pubkey()),
                &[keypair],
                recent_blockhash,
            );
            client.send_and_confirm_transaction(&tx)?;
        }
        None => {
            if client
                .request_airdrop(&participant_pubkey, initial_lamports)
                .is_err()
            {
                let current_balance = client.get_balance(&participant_pubkey)?;
                println!(
                    "Failed to request airdrop. Ensure the fee payer account has sufficient SOL."
                );
                println!("Current participant balance: {}", current_balance);
            }
        }
    }

    //Hack: To await airdrop settlement. Refactor to use async/await with appropriate commitment.
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::native_token::LAMPORTS_PER_SOL;
    use solana_sdk::signer::Signer;
    use utils::get_or_create_keypair;

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn test_setup_basic_participant() -> Result<(), Box<dyn Error>> {
        let participant_keypair = get_or_create_keypair("SOLO_TEST_participant_keypair")?;

        setup_basic_participant(&participant_keypair.pubkey(), None, 2 * LAMPORTS_PER_SOL).await?;
        Ok(())
    }
}
