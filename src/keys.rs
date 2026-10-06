//! Standard confidential-balances key derivation (solana-conf-bal/v1).
//!
//! One signature over the constant message `solana-conf-bal/v1` derives both
//! the ElGamal keypair and the AES key. The keys are bound to the wallet
//! alone, so a wallet derives one key pair for all of its confidential
//! balances, byte-identical to every other standard client (spl-token CLI,
//! @solana-program/token-2022, @solana/zk-sdk, solana-go) for the same wallet.
//!
//! zk-sdk 7 carries this derivation, while the rest of this crate stays on
//! zk-sdk 6.0.1 for proof compatibility with the deployed ZK ElGamal Proof
//! program. The two crate versions have distinct key types with identical
//! byte encodings, so we derive with 7 and rebuild the 6.0.1 types from
//! bytes, the same boundary-sidestepping this crate already does for proof
//! types.

use crate::types::CtResult;
use solana_sdk::signature::Signer;
use solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::{ElGamalKeypair, ElGamalSecretKey},
};

/// Derives the standard wallet-level `(ElGamalKeypair, AeKey)` pair for
/// `signer`, as 6.0.1 types ready for this crate's proof pipeline.
// TODO: call the no-seed derive_confidential_keys(signer) directly once the
// zk-sdk release with the wallet-only API lands (zk-elgamal-proof#533).
pub fn derive_confidential_keys(signer: &dyn Signer) -> CtResult<(ElGamalKeypair, AeKey)> {
    let (elgamal_v7, ae_v7) =
        solana_zk_sdk_v7::encryption::derivation::derive_confidential_keys(signer, b"")
            .map_err(|e| format!("derive confidential keys: {e}"))?;

    let secret = ElGamalSecretKey::try_from(elgamal_v7.secret().as_bytes().as_slice())
        .map_err(|e| format!("rebuild ElGamal secret key: {e}"))?;
    let aes_key = AeKey::from(<[u8; 16]>::from(&ae_v7));

    Ok((ElGamalKeypair::new(secret), aes_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::signature::Keypair;
    use solana_zk_sdk::encryption::elgamal::ElGamalPubkey;

    #[test]
    fn derives_the_canonical_cross_sdk_vector() {
        // The canonical standard-path vector, pinned identically in the
        // solana-zk-sdk Rust tests, the solana-go fixtures
        // (keypair_a_empty_seed) and the Token-2022 JS client tests. This
        // guards the v7-derive-to-v6-types byte crossing: any drift in either
        // crate version or in the reconstruction fails here.
        let signer_seed: [u8; 32] = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
            0xdd, 0xee, 0xff, 0x00,
        ];
        let expected_elgamal_secret: [u8; 32] = [
            0xbe, 0x5c, 0xce, 0x95, 0x1f, 0x42, 0xa2, 0xa8, 0x67, 0x7d, 0x1a, 0x56, 0xf0, 0x3a,
            0xae, 0x7b, 0xff, 0x79, 0x5b, 0x38, 0xcf, 0x1c, 0x56, 0xc8, 0xcf, 0x3a, 0x4d, 0xae,
            0x7d, 0x60, 0xe2, 0x05,
        ];
        let expected_aes: [u8; 16] = [
            0x64, 0x17, 0xee, 0xdb, 0xcb, 0xe9, 0xc6, 0x4a, 0x72, 0x39, 0x57, 0x19, 0xec, 0x98,
            0xcf, 0x6b,
        ];

        let keypair = Keypair::new_from_array(signer_seed);
        let (elgamal, aes) = derive_confidential_keys(&keypair).unwrap();

        assert_eq!(elgamal.secret().as_bytes(), &expected_elgamal_secret);
        assert_eq!(<[u8; 16]>::from(aes), expected_aes);
        // The rebuilt keypair must satisfy the v6 pubkey invariant.
        assert_eq!(*elgamal.pubkey(), ElGamalPubkey::new(elgamal.secret()));
    }

    #[test]
    fn derivation_is_deterministic() {
        let keypair = Keypair::new();
        let (elgamal_a, aes_a) = derive_confidential_keys(&keypair).unwrap();
        let (elgamal_b, aes_b) = derive_confidential_keys(&keypair).unwrap();
        assert_eq!(elgamal_a.secret().as_bytes(), elgamal_b.secret().as_bytes());
        assert_eq!(<[u8; 16]>::from(aes_a), <[u8; 16]>::from(aes_b));
    }
}
