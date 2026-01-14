use {
    jito_sdk_rust::JitoJsonRpcSDK, reqwest, serde_json::Value, solana_instruction::Instruction,
    solana_native_token::LAMPORTS_PER_SOL, solana_pubkey::Pubkey,
    solana_system_interface::instruction as system_instruction, std::str::FromStr,
    std::time::Duration,
};

#[derive(Debug)]
pub struct BundleStatus {
    confirmation_status: Option<String>,
    err: Option<serde_json::Value>,
    transactions: Option<Vec<String>>,
}

pub const MAX_RETRIES: u32 = 40;
pub const RETRY_DELAY: Duration = Duration::from_secs(3);
pub const JITO_ENGINE_URL: &str = "https://dallas.testnet.block-engine.jito.wtf/api/v1";

pub async fn create_jito_tip_instruction(
    sender_pubkey: Pubkey,
) -> Result<Instruction, Box<dyn std::error::Error>> {
    let jito_sdk = JitoJsonRpcSDK::new(JITO_ENGINE_URL, None);

    let random_tip_account = jito_sdk.get_random_tip_account().await?;
    let jito_tip_account = Pubkey::from_str(&random_tip_account)?;
    let jito_tip_amount: u64 = get_max_tip_amount().await?;
    println!("Jito tip lamports: {}", jito_tip_amount);

    Ok(system_instruction::transfer(
        &sender_pubkey,
        &jito_tip_account,
        jito_tip_amount,
    ))
}
pub async fn submit_and_confirm_bundle(
    bundle: serde_json::Value,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let jito_sdk = JitoJsonRpcSDK::new(JITO_ENGINE_URL, None);

    // UUID for the bundle
    let uuid = None;

    // Send bundle using Jito SDK
    println!(
        "Sending bundle with {} transactions...",
        bundle.as_array().unwrap().len()
    );
    let response = jito_sdk.send_bundle(Some(bundle), uuid).await?;

    // Extract bundle UUID from response
    let bundle_uuid = response["result"]
        .as_str()
        .ok_or("Failed to get bundle UUID from response")?;
    println!("Bundle sent with UUID: {}", bundle_uuid);

    confirm_bundle_status(&jito_sdk, &bundle_uuid).await
}
pub async fn confirm_bundle_status(
    jito_sdk: &JitoJsonRpcSDK,
    bundle_uuid: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    for attempt in 1..=MAX_RETRIES {
        println!(
            "Checking bundle status (attempt {}/{})",
            attempt, MAX_RETRIES
        );

        let status_response = jito_sdk
            .get_in_flight_bundle_statuses(vec![bundle_uuid.to_string()])
            .await?;

        if let Some(result) = status_response.get("result") {
            if let Some(value) = result.get("value") {
                if let Some(statuses) = value.as_array() {
                    if let Some(bundle_status) = statuses.get(0) {
                        if let Some(status) = bundle_status.get("status") {
                            match status.as_str() {
                                Some("Landed") => {
                                    println!("Bundle landed on-chain. Checking final status...");
                                    return Ok(
                                        check_final_bundle_status(&jito_sdk, bundle_uuid).await?
                                    );
                                }
                                Some("Pending") => {
                                    println!("Bundle is pending. Waiting...");
                                }
                                Some(status) => {
                                    if status == "Failed" {
                                        return Err(
                                            format!("Bundle failed to land on-chain").into()
                                        );
                                    }
                                    println!("Unexpected bundle status: {}. Waiting...", status);
                                }
                                None => {
                                    println!("Unable to parse bundle status. Waiting...");
                                }
                            }
                        } else {
                            println!("Status field not found in bundle status. Waiting...");
                        }
                    } else {
                        println!("Bundle status not found. Waiting...");
                    }
                } else {
                    println!("Unexpected value format. Waiting...");
                }
            } else {
                println!("Value field not found in result. Waiting...");
            }
        } else if let Some(error) = status_response.get("error") {
            println!("Error checking bundle status: {:?}", error);
        } else {
            println!("Unexpected response format. Waiting...");
        }

        if attempt < MAX_RETRIES {
            std::thread::sleep(RETRY_DELAY);
        }
    }

    Err(format!(
        "Failed to confirm bundle status after {} attempts",
        MAX_RETRIES
    )
    .into())
}

pub async fn get_max_tip_amount() -> Result<u64, Box<dyn std::error::Error>> {
    // Query the API
    let response = reqwest::get("https://bundles.jito.wtf/api/v1/bundles/tip_floor").await?;
    let data: Value = response.json().await?;

    // Parse the JSON to get the 99th percentile tip
    let landed_tips_99th_percentile = data[0]["landed_tips_99th_percentile"]
        .as_f64()
        .ok_or("Failed to parse landed_tips_99th_percentile")?;

    println!(
        "Jito landed_tips_99th_percentile: {}",
        landed_tips_99th_percentile
    );

    // Convert SOL to Lamports
    let jito_tip_amount = (landed_tips_99th_percentile * LAMPORTS_PER_SOL as f64) as u64;

    Ok(jito_tip_amount)
}

async fn check_final_bundle_status(
    jito_sdk: &JitoJsonRpcSDK,
    bundle_uuid: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    for attempt in 1..=MAX_RETRIES {
        println!(
            "Checking final bundle status (attempt {}/{})",
            attempt, MAX_RETRIES
        );

        let status_response = jito_sdk
            .get_bundle_statuses(vec![bundle_uuid.to_string()])
            .await?;
        let bundle_status = get_bundle_status(&status_response)?;

        match bundle_status.confirmation_status.as_deref() {
            Some("confirmed") => {
                println!("Bundle confirmed on-chain. Waiting for finalization...");
                check_transaction_error(&bundle_status)?;
                return match bundle_status.transactions {
                    Some(transactions) => Ok(transactions),
                    None => {
                        Err("Error retrieving transactions from finalized bundle status".into())
                    }
                };
            }
            Some("finalized") => {
                println!("Bundle finalized on-chain successfully!");
                check_transaction_error(&bundle_status)?;
                return match bundle_status.transactions {
                    Some(transactions) => Ok(transactions),
                    None => {
                        Err("Error retrieving transactions from finalized bundle status".into())
                    }
                };
            }
            Some(status) => {
                println!(
                    "Unexpected final bundle status: {}. Continuing to poll...",
                    status
                );
            }
            None => {
                println!("Unable to parse final bundle status. Continuing to poll...");
            }
        }

        if attempt < MAX_RETRIES {
            std::thread::sleep(RETRY_DELAY);
        }
    }

    Err(format!(
        "Failed to get finalized status after {} attempts",
        MAX_RETRIES
    )
    .into())
}

fn get_bundle_status(
    status_response: &serde_json::Value,
) -> Result<BundleStatus, Box<dyn std::error::Error>> {
    status_response
        .get("result")
        .and_then(|result| result.get("value"))
        .and_then(|value| value.as_array())
        .and_then(|statuses| statuses.get(0))
        .ok_or_else(|| format!("Failed to parse bundle status").into())
        .map(|bundle_status| BundleStatus {
            confirmation_status: bundle_status
                .get("confirmation_status")
                .and_then(|s| s.as_str())
                .map(String::from),
            err: bundle_status.get("err").cloned(),
            transactions: bundle_status
                .get("transactions")
                .and_then(|t| t.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
        })
}

fn check_transaction_error(bundle_status: &BundleStatus) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(err) = &bundle_status.err {
        if err["Ok"].is_null() {
            println!("Transaction executed without errors.");
            Ok(())
        } else {
            println!("Transaction encountered an error: {:?}", err);
            Err(format!("Transaction encountered an error").into())
        }
    } else {
        Ok(())
    }
}
