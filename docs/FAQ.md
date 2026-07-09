# FAQ & Troubleshooting

## General Questions

### Can I add confidential transfers to an existing mint?

**No.** Token extensions must be configured at mint creation. However, you can use the [Token Wrap Program](https://github.com/solana-program/token-wrap) to create a wrapped version with confidential transfers enabled.

**Caveat**: Wrapped tokens are recognized as separate mints, which fragments liquidity across the ecosystem.

### What's the difference between pending and available balance?

| Balance | Description | Can Transfer? |
|---------|-------------|---------------|
| **Pending** | Incoming deposits/transfers waiting to be processed | No |
| **Available** | Processed balance ready to spend | Yes |

The two-stage model prevents front-running attacks on ZK proofs.

### Why do transfers require multiple transactions?

ZK proofs are large. A single confidential transfer requires:
- Range proof (~1,400 bytes for U128)
- Equality proof (~192 bytes)
- Ciphertext validity proof (~224 bytes)

These exceed Solana's 1,232-byte transaction limit, requiring proof data to be stored in separate accounts.

### Can I use confidential transfers with PDAs?

**Partially.** PDAs face two challenges:

1. **Key management**: ElGamal keys must be stored somewhere. On-chain storage exposes them.
2. **Proof generation**: ZK proofs require the secret key and are computationally expensive.

**Solution**: Generate proofs client-side, have PDA authorize the transfer after verification.

### What happens if I lose my ElGamal secret key?

**Permanent loss of confidential balance.** The balance cannot be recovered without the secret key.

Keys derived from wallet signature can be regenerated if you have the wallet. Custom keys require secure backup.

## Implementation Issues

### "Proof generation failed"

**Causes**:
1. Insufficient balance for transfer amount
2. Mismatched keypairs (using wrong account's keys)
3. Incorrect opening values

**Debug**:
```rust
// Verify you have sufficient balance
let available = decrypt_balance(&ct_account.available_balance, &elgamal_keypair)?;
assert!(available >= transfer_amount, "Insufficient balance");

// Verify correct keypair derivation
let expected_pubkey = ct_account.elgamal_pubkey;
let derived_pubkey = elgamal_keypair.pubkey();
assert_eq!(expected_pubkey, derived_pubkey.into(), "Wrong keypair");
```

### "Transaction too large"

**Cause**: Trying to include proof data directly in transaction.

**Solution**: Use context state accounts:
```rust
// Instead of inline proof:
let proof_location = ProofLocation::InstructionOffset(...);

// Use context account:
token.confidential_transfer_create_context_state_account(
    &proof_account_pubkey,
    &authority,
    &proof_data,
    true, // split proof for large data
    &signers,
).await?;
```

### "Decryption failed"

**Causes**:
1. Wrong secret key
2. Amount exceeds u32 range (for `decrypt_u32`)
3. Corrupted ciphertext

**Debug**:
```rust
// Try full decryption for large amounts
let discrete_log = ciphertext.decrypt(&secret_key);
match discrete_log.decode_u32() {
    Some(amount) => println!("Amount: {}", amount),
    None => println!("Amount exceeds u32 or decryption failed"),
}
```

### "ApplyPendingBalance failed"

**Cause**: Credit counter mismatch.

**Solution**: Re-fetch account state and use current counter:
```rust
let account_info = token.get_account_info(&token_account).await?;
let ct_extension = account_info.get_extension::<ConfidentialTransferAccount>()?;
let apply_info = ApplyPendingBalanceAccountInfo::new(ct_extension);

// Use fresh counter value
let expected_counter = apply_info.pending_balance_credit_counter();
```

### "Context state account already in use"

**Cause**: Reusing proof account address.

**Solution**: Generate fresh keypair for each proof:
```rust
// Each transfer needs new proof accounts
let equality_proof_account = Keypair::new();
let range_proof_account = Keypair::new();
let validity_proof_account = Keypair::new();
```

## WASM/JavaScript Issues

### "WASM not initialized" (JavaScript/Browser)

**Cause**: Using crypto functions before `init()` in JavaScript/WASM context.

**Solution** (for JavaScript users):
```typescript
import init from '@solana/zk-sdk/web';

// Always await init before any crypto
await init();

// Now safe to use
const keypair = new ElGamalKeypair();
```

**Rust users**: No initialization needed - just use the crates directly.

### "BigInt not supported" (JavaScript)

**Cause**: Using number literals instead of BigInt in JavaScript.

**Solution** (for JavaScript users):
```typescript
// Wrong
const amount = 1000;

// Correct
const amount = 1000n;
// or
const amount = BigInt(1000);
```

**Rust users**: Use native `u64` type - no BigInt needed.

### Bundle size too large (JavaScript/Web)

**Cause**: `@solana/zk-sdk` is ~8MB due to WASM - affects web applications.

**Solutions** (for JavaScript users):
1. Lazy load the crypto module
2. Use code splitting
3. Load WASM from CDN

```typescript
// Lazy load
const zkSdk = await import('@solana/zk-sdk/web');
await zkSdk.default(); // init
```

**Rust users**: Compile natively - no bundle size concerns.

## Transaction Failures

### Partial transfer failure (non-atomic)

**Problem**: Some proof transactions succeeded but transfer failed.

**Recovery options**:

1. **Roll forward**: Retry the transfer instruction
2. **Roll back**: Close proof accounts to reclaim rent

```rust
// Close orphaned proof accounts
for proof_account in orphaned_accounts {
    token.confidential_transfer_close_context_state_account(
        &proof_account,
        &destination,
        &authority,
        &signers,
    ).await?;
}
```

### Jito bundle not landing

**Causes**:
1. Insufficient tip
2. Validator not running Jito
3. Transaction simulation failed

**Solutions**:
1. Increase tip amount
2. Retry with fresh blockhash
3. Check simulation errors before bundling

### "Blockhash expired"

**Cause**: Proof generation took too long.

**Solution**: Generate proofs first, then build transactions:
```rust
// 1. Generate all proofs (slow)
let proofs = generate_transfer_proofs(...)?;

// 2. Get fresh blockhash (fast)
let blockhash = client.get_latest_blockhash()?;

// 3. Build and sign transactions (fast)
let transactions = build_transfer_transactions(proofs, blockhash)?;

// 4. Submit immediately
submit_transactions(transactions)?;
```

## Performance

### Proof generation is slow

**Expected times** (varies by hardware):
- Range proof: 500ms - 2s
- Equality proof: 50ms - 200ms
- Validity proof: 50ms - 200ms

**Optimizations**:
1. Generate proofs in parallel (where possible)
2. Use native Rust instead of WASM
3. Pre-compute proofs before user action

### Decryption is slow for large amounts

**Cause**: Discrete log computation for amounts > 2^32.

**Solutions**:
1. Use `decryptable_available_balance` (AES) for display
2. Keep amounts within u32 range when possible
3. Use `decrypt_u32` for known-small values

## Compute Units

### Transfer exceeds CU limit

**Typical CU usage**:
| Operation | CU |
|-----------|-----|
| Deposit | ~15,000 |
| Apply | ~17,000 |
| Transfer | ~31,000 |
| Withdraw | ~10,000 |

**Solutions**:
1. Request higher CU limit: `SetComputeUnitLimit`
2. Split operations across transactions
3. Use context accounts (cheaper than inline proofs)

## Debugging Tips

### Enable verbose logging

**Rust**:
```rust
env_logger::Builder::from_env(
    env_logger::Env::default().default_filter_or("debug")
).init();
```

**JavaScript** (browser):
```typescript
localStorage.setItem('debug', 'solana:*');
```

### Inspect account state

```bash
# CLI
spl-token display <TOKEN_ACCOUNT>

# Shows confidential transfer extension fields
```

### Verify proof locally before submitting

**Rust**:
```rust
proof_data.verify()?; // Throws if invalid
```

**JavaScript**:
```typescript
proof.verify(); // Throws if invalid
```

## Resources

- [Solana Confidential Transfer Docs](https://solana.com/docs/tokens/extensions/confidential-transfer)
- [Confidential Balances Sample](https://github.com/solana-developers/Confidential-Balances-Sample)
- [Token-2022 CLI Examples](https://github.com/solana-program/token-2022/blob/main/clients/cli/examples/confidential-transfer.sh)
- [Discord: #confidential-transfers](https://discord.gg/solana)
