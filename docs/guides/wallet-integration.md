# Wallet Integration Guide

This guide covers how wallet developers can integrate Solana's Confidential Balances feature using Rust.

## Overview

Wallets integrating confidential transfers need to handle:

1. **Encryption Key Management** - Deriving and storing ElGamal and AES keys
2. **Balance Display** - Decrypting confidential balances for users
3. **Transaction Building** - Creating confidential transfer transactions with proofs
4. **Pending Balance Handling** - Managing the two-stage balance model

## Encryption Key Management

### Key Derivation Process

Each confidential token account requires two encryption keys derived from wallet signatures:

```
┌───────────────────────────────────────────────────────────┐
│                  KEY DERIVATION FLOW                      │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  1. ElGamal Key Derivation                                │
│     ├─ Seed Message: "ElGamalSecretKey"                   │
│     ├─ Sign: wallet.signMessage(seed + publicSeed)        │
│     └─ Derive: ElGamalKeypair.fromSignature(signature)    │
│                                                           │
│  2. AES Key Derivation                                    │
│     ├─ Seed Message: "AeKey"                              │
│     ├─ Sign: wallet.signMessage(seed + publicSeed)        │
│     └─ Derive: AeKey.fromSignature(signature)             │
│                                                           │
└───────────────────────────────────────────────────────────┘
```

### Implementation (Rust)

```rust
use solana_sdk::signer::Signer;
use spl_token_2022::solana_zk_sdk::encryption::{
    auth_encryption::AeKey,
    elgamal::ElGamalKeypair,
};

/// Derive encryption keys for a token account
fn derive_encryption_keys(
    signer: &dyn Signer,
    token_account: &solana_sdk::pubkey::Pubkey,
) -> Result<(ElGamalKeypair, AeKey), Box<dyn std::error::Error>> {
    // Derive ElGamal keypair deterministically from signer
    let elgamal_keypair = ElGamalKeypair::new_from_signer(
        signer,
        &token_account.to_bytes(),
    )?;

    // Derive AES key for efficient balance viewing
    let aes_key = AeKey::new_from_signer(
        signer,
        &token_account.to_bytes(),
    )?;

    Ok((elgamal_keypair, aes_key))
}
```

### Security Considerations

1. **Deterministic Derivation** - Same signature always produces same keys
2. **Key Storage** - Either derive on-the-fly or store encrypted locally
3. **Never Transmit** - Keys must never be shared with unauthorized parties
4. **Backup Critical** - Loss of keys = permanent loss of confidential balance

## Balance Display

### Balance Types in Confidential Accounts

| Balance Type | Encryption | Who Can View |
|--------------|------------|--------------|
| **Public** | None | Anyone |
| **Pending** | ElGamal | Owner (decrypt), Auditor |
| **Available** | ElGamal | Owner (decrypt), Auditor |
| **Decryptable Available** | AES | Owner only (efficient) |

### Decryption Implementation

```rust
use solana_client::rpc_client::RpcClient;
use spl_token_2022::extension::{
    confidential_transfer::ConfidentialTransferAccount,
    BaseStateWithExtensions, StateWithExtensions,
};
use spl_token_2022::state::Account as TokenAccount;
use spl_associated_token_account::get_associated_token_address_with_program_id;

/// Get confidential balance for display
fn get_confidential_balance(
    client: &RpcClient,
    owner: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
) -> Result<u64, Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    // Derive encryption keys
    let (elgamal_keypair, aes_key) = derive_encryption_keys(owner, &token_account)?;

    // Fetch account data
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;

    // Get confidential transfer extension
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Decrypt available balance using AES (most efficient)
    let decryptable_balance: spl_token_2022::solana_zk_sdk::encryption::auth_encryption::AeCiphertext =
        ct_extension.decryptable_available_balance.try_into()?;

    let available_balance = aes_key.decrypt(&decryptable_balance)
        .ok_or("Failed to decrypt balance")?;

    Ok(available_balance)
}

/// Get all balance types for comprehensive display
fn get_all_balances(
    client: &RpcClient,
    owner: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
) -> Result<BalanceBreakdown, Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    let (elgamal_keypair, aes_key) = derive_encryption_keys(owner, &token_account)?;
    let account_data = client.get_account(&token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    // Decrypt pending balance
    let pending_lo: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_lo.try_into()?;
    let pending_hi: spl_token_2022::solana_zk_sdk::encryption::elgamal::ElGamalCiphertext =
        ct_extension.pending_balance_hi.try_into()?;

    let pending_lo_amount = pending_lo.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt pending_lo")?;
    let pending_hi_amount = pending_hi.decrypt_u32(elgamal_keypair.secret())
        .ok_or("Failed to decrypt pending_hi")?;
    let pending_total = pending_lo_amount + (pending_hi_amount << 16);

    // Decrypt available balance
    let decryptable_balance: spl_token_2022::solana_zk_sdk::encryption::auth_encryption::AeCiphertext =
        ct_extension.decryptable_available_balance.try_into()?;
    let available = aes_key.decrypt(&decryptable_balance)
        .ok_or("Failed to decrypt available balance")?;

    Ok(BalanceBreakdown {
        public: account.base.amount,
        pending: pending_total,
        available,
        total: account.base.amount + pending_total + available,
    })
}

#[derive(Debug)]
struct BalanceBreakdown {
    pub public: u64,
    pub pending: u64,
    pub available: u64,
    pub total: u64,
}
```

## Transaction Building

### Transfer Flow for Wallets

```
┌──────────────────────────────────────────────────────────────┐
│                    TRANSFER FLOW                             │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│   Sender                                    Receiver         │
│     │                                          │             │
│     │ ───► DEPOSIT (public → pending)          │             │
│     │ ───► APPLY   (pending → available)       │             │
│     │                                          │             │
│     │ ─────────── TRANSFER ───────────────────►│             │
│     │          (7 transactions)                │             │
│     │                                          │             │
│     │                          APPLY ◄─────────│             │
│     │                          (pending →      │             │
│     │                           available)     │             │
│                                                              │
└──────────────────────────────────────────────────────────────┘
```

### Complete Transfer Implementation

See `src/transfer.rs` for the full implementation. Key steps:

1. **Fetch recipient's ElGamal public key** from their account
2. **Generate ZK proofs** for the transfer
3. **Create proof context state accounts** (3 transactions)
4. **Execute transfer** (1 transaction)
5. **Close proof accounts** (3 instructions)

```rust
use crate::transfer::transfer_confidential;

/// Example: Send confidential transfer
async fn send_confidential_transfer(
    client: &RpcClient,
    payer: &dyn Signer,
    sender: &Keypair,
    mint: &solana_sdk::pubkey::Pubkey,
    recipient: &solana_sdk::pubkey::Pubkey,
    amount: u64,
) -> Result<Vec<solana_sdk::signature::Signature>, Box<dyn std::error::Error>> {
    // The transfer function handles all complexity:
    // - Fetches recipient's ElGamal pubkey from their account
    // - Fetches auditor's ElGamal pubkey from mint
    // - Generates proofs
    // - Creates proof context accounts
    // - Executes transfer
    // - Closes proof accounts
    let signatures = transfer_confidential(
        client,
        payer,
        sender,
        mint,
        recipient,
        amount,
    ).await?;

    println!("Transfer complete with {} transactions", signatures.len());
    Ok(signatures)
}
```

## Pending Balance Management

### Monitoring for Incoming Transfers

```rust
use spl_token_2022::extension::confidential_transfer::ConfidentialTransferAccount;

/// Check if account has pending balance to apply
fn has_pending_balance(
    client: &RpcClient,
    token_account: &solana_sdk::pubkey::Pubkey,
) -> Result<bool, Box<dyn std::error::Error>> {
    let account_data = client.get_account(token_account)?;
    let account = StateWithExtensions::<TokenAccount>::unpack(&account_data.data)?;
    let ct_extension = account.get_extension::<ConfidentialTransferAccount>()?;

    let credit_count: u64 = ct_extension.pending_balance_credit_counter.into();

    Ok(credit_count > 0)
}
```

### Auto-Apply Strategy

```rust
use crate::apply_pending::apply_pending_balance;

/// Automatically apply pending balance if present
async fn auto_apply_pending(
    client: &RpcClient,
    owner: &dyn Signer,
    mint: &solana_sdk::pubkey::Pubkey,
) -> Result<Option<solana_sdk::signature::Signature>, Box<dyn std::error::Error>> {
    let token_account = get_associated_token_address_with_program_id(
        &owner.pubkey(),
        mint,
        &spl_token_2022::id(),
    );

    if !has_pending_balance(client, &token_account)? {
        return Ok(None);
    }

    let signature = apply_pending_balance(client, owner, mint).await?;
    Ok(Some(signature))
}
```

## UX Recommendations

### 1. Balance Display

```
┌────────────────────────────────────────────────────────────┐
│                    BALANCE DISPLAY                         │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Token: USDC (Confidential)                                │
│                                                            │
│  Available Balance:     1,234.56 USDC                      │
│  Pending Balance:         100.00 USDC  [Apply]             │
│  Public Balance:           50.00 USDC                      │
│  ─────────────────────────────────────                     │
│  Total:                 1,384.56 USDC                      │
│                                                            │
│  [Deposit] [Withdraw] [Transfer]                           │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 2. Transaction Signing

Present multi-tx operations as single action:

```
┌────────────────────────────────────────────────────────────┐
│                  CONFIRM TRANSFER                          │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Sending:     100.00 USDC                                  │
│  To:          Bob.sol                                      │
│  Type:        Confidential Transfer                        │
│                                                            │
│  ⚠️  This will require 7 transaction signatures            │
│                                                            │
│  Estimated fees: ~0.01 SOL                                 │
│                                                            │
│            [Cancel]        [Confirm & Sign All]            │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

### 3. Error Handling

| Error | User Message | Action |
|-------|--------------|--------|
| Insufficient balance | "Insufficient confidential balance" | Show available vs requested |
| Pending not applied | "Please apply pending balance first" | Auto-apply or prompt |
| Proof generation failed | "Failed to generate transfer proof" | Retry or contact support |
| Transaction timeout | "Transfer incomplete - checking status" | Check and resume |

## Testing

### Local Validator Setup

```bash
# Start local validator with token-2022
solana-test-validator --quiet --reset &

# Run integration tests
cargo test --test integration_test

# Run end-to-end transfer example
cargo run --example run_transfer
```

### Test Checklist

- [ ] Key derivation produces consistent results
- [ ] Balance decryption shows correct values
- [ ] Deposit → Apply → Transfer → Apply flow works
- [ ] Withdrawal with proof generation succeeds
- [ ] Error states are handled gracefully
- [ ] Recovery from partial failures works

## Resources

- [Confidential Balances Sample (Rust)](https://github.com/solana-developers/Confidential-Balances-Sample)
- [Token-2022 CLI Examples](https://github.com/solana-program/token-2022/blob/main/clients/cli/examples/confidential-transfer.sh)
- [QuickNode Integration Guide](https://www.quicknode.com/guides/solana-development/spl-tokens/token-2022/confidential)
- [This Repository's Implementation](../../src) - Production-ready Rust code
