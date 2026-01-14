use std::error::Error;

use base64::Engine;

use google_cloud_kms::{
    client::{Client, ClientConfig},
    grpc::kms::v1::{AsymmetricSignRequest, GetPublicKeyRequest},
};
use solana_sdk::pubkey::Pubkey;

pub struct GcpSigner {
    client: Client,

    // Example: "projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*"
    resource_name: String,
}

impl GcpSigner {
    pub async fn new(resource_name: String) -> Result<Self, Box<dyn Error>> {
        let config = ClientConfig::default().with_auth().await?;
        let client = Client::new(config).await?;
        Ok(Self {
            client,
            resource_name: resource_name,
        })
    }
}

fn decode_pem(pem: &str) -> Result<Pubkey, Box<dyn Error>> {
    // Step 1: Strip PEM headers
    let pem_body = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    // Step 2: Decode the base64 PEM body
    let der_bytes = base64::engine::general_purpose::STANDARD.decode(&pem_body)?;

    // Step 3: Extract the raw public key
    // For Ed25519, the raw key is the last 32 bytes of the DER structure
    let raw_key = &der_bytes[der_bytes.len() - 32..];

    // Step 4: Convert the raw key to a Pubkey
    Pubkey::try_from(raw_key).map_err(|e| Box::new(e) as Box<dyn Error>)
}

impl solana_sdk::signer::Signer for GcpSigner {
    fn try_pubkey(&self) -> Result<Pubkey, solana_sdk::signer::SignerError> {
        // START Blocking thread...
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                // START logic
                let resp = self
                    .client
                    .get_public_key(
                        GetPublicKeyRequest {
                            name: self.resource_name.clone(),
                        },
                        None,
                    )
                    .await
                    .map_err(|e| solana_sdk::signer::SignerError::Custom(e.to_string()));

                decode_pem(&resp.unwrap().pem)
                    .map_err(|e| solana_sdk::signer::SignerError::Custom(e.to_string()))
                // END logic
            })
        })
        // END Blocking thread...
    }

    fn try_sign_message(
        &self,
        message: &[u8],
    ) -> Result<solana_sdk::signature::Signature, solana_sdk::signer::SignerError> {
        // START Blocking thread...
        tokio::task::block_in_place(|| {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                // START logic
                let resp = self
                    .client
                    .asymmetric_sign(
                        AsymmetricSignRequest {
                            name: self.resource_name.clone(),
                            digest: None,
                            digest_crc32c: None,
                            data: message.to_vec(),
                            data_crc32c: None,
                        },
                        None,
                    )
                    .await
                    .map_err(|e| solana_sdk::signer::SignerError::Custom(e.to_string()))?;

                let signature_bytes: [u8; 64] =
                    resp.signature.as_slice().try_into().map_err(|_| {
                        solana_sdk::signer::SignerError::Custom(
                            "Invalid signature length".to_string(),
                        )
                    })?;
                let signature = solana_sdk::signature::Signature::from(signature_bytes);
                Ok(signature)
                // END logic
            })
        })
        // END Blocking thread...
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

mod gcp_test {
    #[cfg(test)]
    use super::*;
    #[cfg(test)]
    use dotenvy;
    #[cfg(test)]
    use google_cloud_kms::grpc::kms::v1::ListKeyRingsRequest;
    #[cfg(test)]
    use solana_sdk::signer::Signer;

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_signer() -> Result<(), Box<dyn Error>> {
        dotenvy::from_filename_override(crate::ENV_FILE_PATH).ok();

        let signer = GcpSigner::new("projects/cookbook-448105/locations/us-west1/keyRings/test/cryptoKeys/first_key/cryptoKeyVersions/1".to_string()).await?;
        let pubkey = signer.try_pubkey()?;
        println!("Pubkey: {:?}", pubkey);

        let signature = signer.try_sign_message(b"HelloWorld!")?;
        println!("Signature: {:?}", hex::encode(signature.as_ref()));
        Ok(())
    }

    #[tokio::test]
    async fn test_gcp() -> Result<(), Box<dyn Error>> {
        dotenvy::from_filename_override(crate::ENV_FILE_PATH).ok();

        let config = ClientConfig::default().with_auth().await?;
        let client = Client::new(config).await?;

        // list
        match client
            .list_key_rings(
                ListKeyRingsRequest {
                    parent: "projects/cookbook-448105/locations/us-west1".to_string(),
                    page_size: 5,
                    page_token: "".to_string(),
                    filter: "".to_string(),
                    order_by: "".to_string(),
                },
                None,
            )
            .await
        {
            Ok(response) => {
                println!("List key rings");
                for r in response.key_rings {
                    println!("- {:?}", r);
                }
            }
            Err(err) => panic!("err: {:?}", err),
        };

        // get
        match client
            .get_public_key(
                GetPublicKeyRequest {
                    name: "projects/cookbook-448105/locations/us-west1/keyRings/test/cryptoKeys/first_key/cryptoKeyVersions/1"
                        .to_string(),
                },
                None,
            )
            .await
        {
            Ok(response) => {
                println!("Get keyring: {:?}", response);
            }
            Err(err) => panic!("err: {:?}", err),
        }

        let resp =client.asymmetric_sign(
            AsymmetricSignRequest {
                name: "projects/cookbook-448105/locations/us-west1/keyRings/test/cryptoKeys/first_key/cryptoKeyVersions/1"
                    .to_string(),
                digest: None,
                digest_crc32c: None,
                data: b"HelloWorld!".to_vec(),
                data_crc32c: None,
            },
            None,
        ).await?;

        println!("Signature: {:?}", hex::encode(&resp.signature));

        Ok(())
    }
}
