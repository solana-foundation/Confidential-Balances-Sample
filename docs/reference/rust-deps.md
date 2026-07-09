# Rust Dependencies Reference

This document covers the Rust crates used for Solana Confidential Balances.

## Crate Overview

```toml
[dependencies]
# Solana Core
solana-sdk = "3.0.0"
solana-client = "3.1.6"
solana-zk-sdk = "6.0.1"  # matches the deployed devnet ZK ElGamal Proof program

# SPL Token-2022
spl-token-2022 = "10.0.0"  # still uses zk-sdk 4.0 transitively
spl-token-client = "0.18.0"
spl-associated-token-account = "8.0.0"

# Confidential Transfer Proof Generation
spl-token-confidential-transfer-proof-generation = "0.6.0"   # zk-sdk 6.0.1
spl-token-confidential-transfer-proof-extraction = "0.5.1"   # zk-sdk 4.0, for the legacy ProofLocation type
```

> The 4.0 ↔ 6.0.1 split is a stopgap until the agave v4 beta / rc crates of
> `spl-token-client` and `spl-token-2022` are published. See the **Bypass
> mode** section in the top-level README for how the boundary is bridged in
> the meantime.

## solana-zk-sdk

The core cryptographic SDK for zero-knowledge proofs.

**Repository**: [solana-program/zk-elgamal-proof](https://github.com/solana-program/zk-elgamal-proof)

### Key Generation

```rust
use solana_zk_sdk::encryption::elgamal::{ElGamalKeypair, ElGamalPubkey, ElGamalSecretKey};

// Random keypair
let keypair = ElGamalKeypair::new_rand();

// From signer (deterministic)
let keypair = ElGamalKeypair::new_from_signer(&signer, &token_account.to_bytes())?;

// From existing secret key
let secret = ElGamalSecretKey::new_rand();
let keypair = ElGamalKeypair::new(secret);

// Access components
let pubkey: &ElGamalPubkey = keypair.pubkey();
let secret: &ElGamalSecretKey = keypair.secret();
```

### Encryption

```rust
use solana_zk_sdk::encryption::elgamal::{ElGamalCiphertext, ElGamalPubkey};
use solana_zk_sdk::encryption::pedersen::PedersenOpening;

let pubkey: &ElGamalPubkey = /* ... */;
let amount: u64 = 1000;

// Basic encryption (random opening)
let ciphertext: ElGamalCiphertext = pubkey.encrypt(amount);

// With specific opening (for proofs)
let opening = PedersenOpening::new_rand();
let ciphertext = pubkey.encrypt_with(amount, &opening);
```

### Decryption

```rust
let secret_key: &ElGamalSecretKey = /* ... */;
let ciphertext: &ElGamalCiphertext = /* ... */;

// For small values (u32 range) - non-constant time
let decrypted: Option<u64> = ciphertext.decrypt_u32(secret_key);

// For larger values - uses discrete log
let discrete_log = ciphertext.decrypt(secret_key);
let decrypted = discrete_log.decode();
```

### Homomorphic Operations

```rust
// Ciphertexts support arithmetic
let sum = ciphertext1 + ciphertext2;       // Add encrypted values
let diff = ciphertext1 - ciphertext2;      // Subtract
let scaled = ciphertext * 2u64;            // Scalar multiplication

// Example: Update balance after transfer
let new_balance_ct = current_balance_ct - transfer_amount_ct;
```

### Authenticated Encryption (AES)

```rust
use solana_zk_sdk::encryption::auth_encryption::AeKey;

// Generate key
let ae_key = AeKey::new_rand();

// From signer (deterministic)
let ae_key = AeKey::new_from_signer(&signer, &token_account.to_bytes())?;

// Encrypt balance for owner-only decryption
let ciphertext = ae_key.encrypt(balance);

// Decrypt
let balance = ae_key.decrypt(&ciphertext)?;
```

### Pedersen Commitments

```rust
use solana_zk_sdk::encryption::pedersen::{Pedersen, PedersenCommitment, PedersenOpening};

let amount: u64 = 1000;

// Create commitment with random opening
let (commitment, opening) = Pedersen::new(amount);

// Create with specific opening
let opening = PedersenOpening::new_rand();
let commitment = Pedersen::with(amount, &opening);
```

## spl-token-confidential-transfer-proof-generation

High-level proof generation for confidential transfers.

### Transfer Proofs

```rust
use spl_token_confidential_transfer_proof_generation::transfer::TransferProofData;
use spl_token_2022::extension::confidential_transfer::account_info::TransferAccountInfo;

let sender_account_info = TransferAccountInfo::new(sender_ct_account);

let TransferProofData {
    equality_proof_data,
    ciphertext_validity_proof_data_with_ciphertext,
    range_proof_data,
} = sender_account_info.generate_split_transfer_proof_data(
    transfer_amount,
    &sender_elgamal_keypair,
    &sender_aes_key,
    &recipient_elgamal_pubkey,
    Some(&auditor_elgamal_pubkey),
)?;
```

### Withdraw Proofs

```rust
use spl_token_confidential_transfer_proof_generation::withdraw::WithdrawProofData;
use spl_token_2022::extension::confidential_transfer::account_info::WithdrawAccountInfo;

let withdraw_account_info = WithdrawAccountInfo::new(ct_account);

let WithdrawProofData {
    equality_proof_data,
    range_proof_data,
} = withdraw_account_info.generate_proof_data(
    withdraw_amount,
    &elgamal_keypair,
    &aes_key,
)?;
```

## spl-token-2022

### Confidential Transfer Extension Types

```rust
use spl_token_2022::extension::confidential_transfer::{
    ConfidentialTransferAccount,
    ConfidentialTransferMint,
};

// Access extension from account
use spl_token_2022::extension::BaseStateWithExtensions;

let account = StateWithExtensionsOwned::<Account>::unpack(account_data)?;
let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

// Fields available
let approved: bool = ct_extension.approved.into();
let elgamal_pubkey = ct_extension.elgamal_pubkey;
let pending_balance_lo = ct_extension.pending_balance_lo;
let pending_balance_hi = ct_extension.pending_balance_hi;
let available_balance = ct_extension.available_balance;
let decryptable_available_balance = ct_extension.decryptable_available_balance;
```

### Instructions

```rust
use spl_token_2022::extension::confidential_transfer::instruction;

// Deposit
let deposit_ix = instruction::deposit(
    &spl_token_2022::id(),
    &token_account,
    &mint,
    deposit_amount,
    decimals,
    &authority,
    &[&authority],
)?;

// Apply Pending Balance
let apply_ix = instruction::apply_pending_balance(
    &spl_token_2022::id(),
    &token_account,
    expected_pending_balance_credit_counter,
    &new_decryptable_available_balance.into(),
    &authority,
    &[&authority],
)?;

// Configure Account
let configure_ix = instruction::configure_account(
    &spl_token_2022::id(),
    &token_account,
    &mint,
    &decryptable_balance.into(),
    maximum_pending_balance_credit_counter,
    &authority,
    &[],
    proof_location,
)?;
```

## spl-token-client

High-level async client for Token-2022 operations.

```rust
use spl_token_client::{
    client::{ProgramRpcClient, ProgramRpcClientSendTransaction},
    token::{Token, ProofAccount, ProofAccountWithCiphertext},
};

// Create token client
let program_client = ProgramRpcClient::new(
    Arc::new(rpc_client),
    ProgramRpcClientSendTransaction,
);

let token = Token::new(
    Arc::new(program_client),
    &spl_token_2022::id(),
    &mint_pubkey,
    Some(decimals),
    fee_payer.clone(),
);

// Confidential transfer
token.confidential_transfer_transfer_tx(
    &sender_token_account,
    &recipient_token_account,
    &sender_authority,
    Some(&equality_proof_account),
    Some(&ciphertext_validity_proof_account),
    Some(&range_proof_account),
    transfer_amount,
    Some(sender_account_info),
    &sender_elgamal_keypair,
    &sender_aes_key,
    &recipient_elgamal_pubkey,
    Some(&auditor_elgamal_pubkey),
    &[&sender_keypair],
).await?;

// Create proof context state account
token.confidential_transfer_create_context_state_account(
    &context_state_pubkey,
    &context_state_authority,
    &proof_data,
    false,  // is_close_account
    &signers,
).await?;

// Withdraw
token.confidential_transfer_withdraw(
    &token_account,
    &authority,
    Some(&ProofAccount::ContextAccount(equality_proof_pubkey)),
    Some(&ProofAccount::ContextAccount(range_proof_pubkey)),
    withdraw_amount,
    decimals,
    Some(withdraw_account_info),
    &elgamal_keypair,
    &aes_key,
    &signers,
).await?;
```

## ZK Proof Program Instructions

```rust
use spl_token_2022::solana_zk_sdk::zk_elgamal_proof_program::{
    self,
    instruction::{close_context_state, ContextStateInfo},
};

// Close context state account (reclaim rent)
let close_ix = close_context_state(
    ContextStateInfo {
        context_state_account: &proof_account_pubkey,
        context_state_authority: &authority_pubkey,
    },
    &rent_destination,
);
```

## Complete Example: Confidential Transfer

```rust
use solana_sdk::{
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use spl_token_2022::{
    extension::confidential_transfer::{
        account_info::TransferAccountInfo,
        ConfidentialTransferAccount,
    },
    solana_zk_sdk::encryption::{
        auth_encryption::AeKey,
        elgamal::ElGamalKeypair,
    },
};
use spl_token_client::token::{ProofAccount, ProofAccountWithCiphertext, Token};
use spl_token_confidential_transfer_proof_generation::transfer::TransferProofData;

async fn confidential_transfer(
    token: &Token<impl ProgramClient>,
    sender_keypair: &Keypair,
    sender_token_account: &Pubkey,
    recipient_token_account: &Pubkey,
    recipient_elgamal_pubkey: &ElGamalPubkey,
    auditor_elgamal_pubkey: Option<&ElGamalPubkey>,
    transfer_amount: u64,
) -> Result<(), Box<dyn Error>> {
    // 1. Derive sender's encryption keys
    let sender_elgamal_keypair = ElGamalKeypair::new_from_signer(
        sender_keypair,
        &sender_token_account.to_bytes(),
    )?;
    let sender_aes_key = AeKey::new_from_signer(
        sender_keypair,
        &sender_token_account.to_bytes(),
    )?;
    
    // 2. Get sender account state
    let sender_account_info = token.get_account_info(sender_token_account).await?;
    let ct_extension = sender_account_info.get_extension::<ConfidentialTransferAccount>()?;
    let transfer_account_info = TransferAccountInfo::new(ct_extension);
    
    // 3. Generate proof data
    let TransferProofData {
        equality_proof_data,
        ciphertext_validity_proof_data_with_ciphertext,
        range_proof_data,
    } = transfer_account_info.generate_split_transfer_proof_data(
        transfer_amount,
        &sender_elgamal_keypair,
        &sender_aes_key,
        recipient_elgamal_pubkey,
        auditor_elgamal_pubkey,
    )?;
    
    // 4. Create proof context state accounts
    let equality_proof_account = Keypair::new();
    let ciphertext_validity_proof_account = Keypair::new();
    let range_proof_account = Keypair::new();
    
    token.confidential_transfer_create_context_state_account(
        &equality_proof_account.pubkey(),
        &sender_keypair.pubkey(),
        &equality_proof_data,
        false,
        &[&equality_proof_account],
    ).await?;
    
    token.confidential_transfer_create_context_state_account(
        &ciphertext_validity_proof_account.pubkey(),
        &sender_keypair.pubkey(),
        &ciphertext_validity_proof_data_with_ciphertext.proof_data,
        false,
        &[&ciphertext_validity_proof_account],
    ).await?;
    
    token.confidential_transfer_create_context_state_account(
        &range_proof_account.pubkey(),
        &sender_keypair.pubkey(),
        &range_proof_data,
        true,  // requires split proof
        &[&range_proof_account],
    ).await?;
    
    // 5. Execute transfer
    let equality_proof = ProofAccount::ContextAccount(equality_proof_account.pubkey());
    let ciphertext_validity_proof = ProofAccountWithCiphertext {
        proof_account: ProofAccount::ContextAccount(ciphertext_validity_proof_account.pubkey()),
        ciphertext_lo: ciphertext_validity_proof_data_with_ciphertext.ciphertext_lo,
        ciphertext_hi: ciphertext_validity_proof_data_with_ciphertext.ciphertext_hi,
    };
    let range_proof = ProofAccount::ContextAccount(range_proof_account.pubkey());
    
    token.confidential_transfer_transfer_tx(
        sender_token_account,
        recipient_token_account,
        &sender_keypair.pubkey(),
        Some(&equality_proof),
        Some(&ciphertext_validity_proof),
        Some(&range_proof),
        transfer_amount,
        Some(transfer_account_info),
        &sender_elgamal_keypair,
        &sender_aes_key,
        recipient_elgamal_pubkey,
        auditor_elgamal_pubkey,
        &[sender_keypair],
    ).await?;
    
    // 6. Close proof accounts (reclaim rent)
    token.confidential_transfer_close_context_state_account(
        &equality_proof_account.pubkey(),
        sender_token_account,
        &sender_keypair.pubkey(),
        &[sender_keypair],
    ).await?;
    
    token.confidential_transfer_close_context_state_account(
        &ciphertext_validity_proof_account.pubkey(),
        sender_token_account,
        &sender_keypair.pubkey(),
        &[sender_keypair],
    ).await?;
    
    token.confidential_transfer_close_context_state_account(
        &range_proof_account.pubkey(),
        sender_token_account,
        &sender_keypair.pubkey(),
        &[sender_keypair],
    ).await?;
    
    Ok(())
}
```

## Migration from Legacy SDK

If migrating from `solana-zk-token-sdk`:

```rust
// OLD (deprecated)
use solana_zk_token_sdk::encryption::elgamal::ElGamalKeypair;

// NEW (current)
use solana_zk_sdk::encryption::elgamal::ElGamalKeypair;
```

APIs are largely compatible, but verify specific functions.

## Resources

- [solana-zk-sdk on docs.rs](https://docs.rs/solana-zk-sdk)
- [spl-token-2022 on docs.rs](https://docs.rs/spl-token-2022)
- [Confidential Balances Sample](https://github.com/solana-developers/Confidential-Balances-Sample)
- [Token-2022 Repository](https://github.com/solana-program/token-2022)
