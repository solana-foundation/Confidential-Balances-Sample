use std::{error::Error, str::FromStr};

use bs58;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_transaction_status_client_types::{
    EncodedTransaction, UiMessage, UiTransactionEncoding,
};
use spl_token_2022::{
    extension::confidential_transfer::instruction::TransferInstructionData,
    instruction::decode_instruction_data,
    solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalKeypair},
};
use utils::{get_rpc_client, load_value};

use solana_commitment_config::CommitmentConfig;
use solana_sdk::signature::Signature;

use spl_token_confidential_transfer_proof_generation::{
    try_combine_lo_hi_ciphertexts, TRANSFER_AMOUNT_LO_BITS,
};

pub async fn last_transfer_amount(
    asserting_amount: u64,
    auditor_keypair: &ElGamalKeypair,
) -> Result<(), Box<dyn Error>> {
    // Load the last confidential transfer signature from storage
    let loaded_signature: String = load_value("last_confidential_transfer_signature")?;

    // Convert the loaded signature string into a Signature object
    let signature = Signature::from_str(loaded_signature.as_str())?;

    // Get the RPC client to interact with the blockchain
    let client = get_rpc_client()?;

    // Configure the transaction request with specific encoding and commitment settings
    let config = RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    // Fetch the transaction details using the signature and configuration
    let tx = client.get_transaction_with_config(&signature, config)?;

    // Extract the transaction's message to process it
    match tx.transaction.transaction {
        EncodedTransaction::Json(ui_transaction) => {
            if let UiMessage::Raw(raw_message) = ui_transaction.message {
                // Decode the base58 encoded instruction data
                let input = bs58::decode(raw_message.instructions[0].data.clone())
                    .into_vec()
                    .map_err(|e| format!("Base58 decode error: {:?}", e))?;

                // Trim the token instruction type from the input
                let input = &input[1..];

                // Decode the instruction data into a TransferInstructionData object
                let decoded_instruction: TransferInstructionData =
                    *decode_instruction_data(&input)?;

                // Extract and convert the low and high ciphertext parts
                let ct_pod_lo = decoded_instruction.transfer_amount_auditor_ciphertext_lo;
                let ct_lo = ElGamalCiphertext::try_from(ct_pod_lo)?;
                let ct_pod_hi = decoded_instruction.transfer_amount_auditor_ciphertext_hi;
                let ct_hi = ElGamalCiphertext::try_from(ct_pod_hi)?;

                // Combine the low and high ciphertexts to get the full transfer amount ciphertext
                let transfer_amount_auditor_ciphertext =
                    try_combine_lo_hi_ciphertexts(&ct_lo, &ct_hi, TRANSFER_AMOUNT_LO_BITS)
                        .ok_or(format!("Failed to combine ciphertexts"))?;

                // Decrypt the transfer amount using the auditor's secret key
                let decrypted_amount = auditor_keypair
                    .secret()
                    .decrypt(&transfer_amount_auditor_ciphertext);

                // Decode the decrypted amount and assert it matches the expected asserting amount
                let decrypted_decoded_amount = decrypted_amount
                    .decode_u32()
                    .ok_or(format!("Failed to decode u32"))?;
                assert_eq!(decrypted_decoded_amount, asserting_amount);
            }
        }
        // Handle unexpected transaction encoding
        _ => println!("Unexpected transaction encoding"),
    }

    Ok(())
}
