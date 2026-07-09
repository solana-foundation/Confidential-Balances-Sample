# Token Extensions (Token-2022) Program Architecture

This document provides a deep dive into how confidential transfers work at the Token Extensions (Token-2022) program level.

## Token-2022 vs Token (SPL) Program

| Aspect | Token (SPL) | Token-2022 |
|--------|-------------|------------|
| **Program ID** | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb` |
| **Extensions Support** | No | Yes |
| **Account Size** | Fixed (165 bytes) | Variable (based on extensions) |
| **Backwards Compatible** | N/A | Yes (standard token operations work) |
| **Confidential Transfers** | No | Yes (via extensions) |

## Extension System Architecture

### What are Extensions?

Token-2022 introduces an **extension system** that allows additional functionality to be added to mints and token accounts without breaking existing behavior. Extensions are modular features that can be enabled selectively.

```
┌─────────────────────────────────────────────────────────────┐
│                  TOKEN-2022 EXTENSION SYSTEM                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────┐      ┌────────────────────┐         │
│  │   Base Account     │      │  Extension Data    │         │
│  │   (165 bytes)      │──────│  (Variable size)   │         │
│  │                    │      │                    │         │
│  │  • Owner           │      │  Extension 1       │         │
│  │  • Mint            │      │  Extension 2       │         │
│  │  • Amount          │      │  Extension 3       │         │
│  │  • Delegate        │      │  ...               │         │
│  │  • State           │      │                    │         │
│  └────────────────────┘      └────────────────────┘         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Extension Rules

1. **Immutable after creation**: Extensions cannot be added or removed after mint/account creation
2. **Must be initialized in order**: Mint extensions → Account extensions
3. **Space allocation**: Accounts must be reallocated to fit extension data
4. **Type-specific**: Mint extensions vs Account extensions are separate

## Extensions for Confidential Transfers

### Required Extensions

| Extension | Applied To | Required For | Purpose |
|-----------|-----------|--------------|---------|
| **ConfidentialTransferMint** | Mint | All confidential tokens | Configures mint-level settings (auditor, authority, auto-approval) |
| **ConfidentialTransferAccount** | Token Account | Confidential operations | Stores encrypted balances and encryption keys |

### Optional Extensions

| Extension | Applied To | Use Case |
|-----------|-----------|----------|
| **ConfidentialTransferFeeConfig** | Mint | Tokens with transfer fees | Enables confidential fee calculation |
| **ConfidentialMintBurn** | Mint | Private token issuance | Allows minting/burning without public visibility |

### Extension Combinations

```
Valid Combinations:
├─ Confidential Transfer only
│  └─ ConfidentialTransferMint + ConfidentialTransferAccount
│
├─ Confidential Transfer + Fees
│  └─ ConfidentialTransferMint + ConfidentialTransferFeeConfig + ConfidentialTransferAccount
│
└─ Confidential Transfer + MintBurn
   └─ ConfidentialTransferMint + ConfidentialMintBurn + ConfidentialTransferAccount

Note: ConfidentialMintBurn disables Deposit/Withdraw operations
```

## Account Structure with Extensions

### Mint Account with ConfidentialTransferMint Extension

```
┌───────────────────────────────────────────────────────────┐
│                      MINT ACCOUNT                         │
├───────────────────────────────────────────────────────────┤
│                                                           │
│  Base Mint Data (82 bytes):                               │
│  ├─ mint_authority: Option<Pubkey>                        │
│  ├─ supply: u64                                           │
│  ├─ decimals: u8                                          │
│  ├─ is_initialized: bool                                  │
│  ├─ freeze_authority: Option<Pubkey>                      │
│  └─ account_type: AccountType                             │
│                                                           │
│  Extension Metadata:                                      │
│  ├─ extension_type: u16 (ConfidentialTransferMint = 11)   │
│  └─ length: u16                                           │
│                                                           │
│  ConfidentialTransferMint Data (101 bytes):               │
│  ├─ authority: Option<Pubkey> (33 bytes)                  │
│  ├─ auto_approve_new_accounts: bool (1 byte)              │
│  ├─ auditor_elgamal_pubkey: Option<ElGamalPubkey>         │
│  │  (33 bytes, for compliance/auditing)                   │
│  └─ withdraw_withheld_authority_elgamal_pubkey:           │
│     Option<ElGamalPubkey> (33 bytes, for fee collection)  │
│                                                           │
└───────────────────────────────────────────────────────────┘
Total Size: 82 + 4 + 101 = 187 bytes (minimum)
```

### Token Account with ConfidentialTransferAccount Extension

```
┌────────────────────────────────────────────────────────────┐
│                   TOKEN ACCOUNT                            │
├────────────────────────────────────────────────────────────┤
│                                                            │
│  Base Account Data (165 bytes):                            │
│  ├─ mint: Pubkey                                           │
│  ├─ owner: Pubkey                                          │
│  ├─ amount: u64 (public balance)                           │
│  ├─ delegate: Option<Pubkey>                               │
│  ├─ state: AccountState                                    │
│  ├─ is_native: Option<u64>                                 │
│  ├─ delegated_amount: u64                                  │
│  ├─ close_authority: Option<Pubkey>                        │
│  └─ account_type: AccountType                              │
│                                                            │
│  Extension Metadata:                                       │
│  ├─ extension_type: u16 (ConfidentialTransferAccount = 12) │
│  └─ length: u16                                            │
│                                                            │
│  ConfidentialTransferAccount Data (286 bytes):             │
│  ├─ approved: PodBool (1 byte)                             │
│  │  Whether account is approved for confidential ops       │
│  ├─ elgamal_pubkey: ElGamalPubkey (32 bytes)               │
│  │  Public encryption key for this account                 │
│  ├─ pending_balance_lo: ElGamalCiphertext (64 bytes)       │
│  │  Encrypted pending balance (lower 64 bits)              │
│  ├─ pending_balance_hi: ElGamalCiphertext (64 bytes)       │
│  │  Encrypted pending balance (upper 64 bits)              │
│  ├─ available_balance: ElGamalCiphertext (64 bytes)        │
│  │  Encrypted available balance (for transfers)            │
│  ├─ decryptable_available_balance: AeCiphertext            │
│  │  (36 bytes, AES-encrypted for fast owner decryption)    │
│  ├─ allow_confidential_credits: PodBool (1 byte)           │
│  │  Accept incoming confidential transfers                 │
│  ├─ allow_non_confidential_credits: PodBool (1 byte)       │
│  │  Accept incoming non-confidential transfers             │
│  ├─ pending_balance_credit_counter: u64 (8 bytes)          │
│  │  Number of unprocessed credits (prevents front-running) │
│  ├─ maximum_pending_balance_credit_counter: u64 (8 bytes)  │
│  │  Max allowed pending credits before apply required      │
│  ├─ expected_pending_balance_credit_counter: u64 (8 bytes) │
│  │  Expected counter for apply instruction                 │
│  └─ actual_pending_balance_credit_counter: u64 (8 bytes)   │
│     Actual counter value                                   │
│                                                            │
└────────────────────────────────────────────────────────────┘
Total Size: 165 + 4 + 286 = 455 bytes (minimum)
```

## Extension Initialization Process

### 1. Initialize Mint with Confidential Transfer

```rust
use spl_token_2022::{
    extension::{
        ExtensionType,
        confidential_transfer::{ConfidentialTransferMint, instruction::initialize_mint},
    },
    instruction::initialize_mint as initialize_base_mint,
    state::Mint,
};

// Step 1: Calculate space needed
let extension_types = vec![ExtensionType::ConfidentialTransferMint];
let space = ExtensionType::try_calculate_account_len::<Mint>(&extension_types)?;

// Step 2: Create account with sufficient space
let create_account_ix = system_instruction::create_account(
    &payer.pubkey(),
    &mint_pubkey,
    minimum_balance_for_rent_exemption(space),
    space as u64,
    &spl_token_2022::id(),
);

// Step 3: Initialize ConfidentialTransferMint extension
let init_ct_mint_ix = initialize_mint(
    &spl_token_2022::id(),
    &mint_pubkey,
    Some(authority),           // Confidential transfer authority
    auto_approve_new_accounts, // Auto-approve setting
    Some(auditor_pubkey),      // Optional auditor ElGamal key
)?;

// Step 4: Initialize base mint
let init_mint_ix = initialize_base_mint(
    &spl_token_2022::id(),
    &mint_pubkey,
    &mint_authority,
    Some(&freeze_authority),
    decimals,
)?;

// Execute in single transaction
let tx = Transaction::new_signed_with_payer(
    &[create_account_ix, init_ct_mint_ix, init_mint_ix],
    Some(&payer.pubkey()),
    &[&payer, &mint_keypair],
    recent_blockhash,
);
```

**Critical Order**:
1. Create account with sufficient space
2. Initialize extension(s) FIRST
3. Initialize base mint LAST

### 2. Create and Configure Token Account

```rust
use spl_token_2022::extension::confidential_transfer::instruction::{
    configure_account,
    approve_account,
};

// Step 1: Calculate space for token account with extension
let extension_types = vec![ExtensionType::ConfidentialTransferAccount];
let space = ExtensionType::try_calculate_account_len::<Account>(&extension_types)?;

// Step 2: Create account
let create_account_ix = system_instruction::create_account(
    &payer.pubkey(),
    &token_account_pubkey,
    minimum_balance_for_rent_exemption(space),
    space as u64,
    &spl_token_2022::id(),
);

// Step 3: Initialize base token account
let init_account_ix = spl_token_2022::instruction::initialize_account3(
    &spl_token_2022::id(),
    &token_account_pubkey,
    &mint_pubkey,
    &owner_pubkey,
)?;

// Step 4: Configure confidential transfer extension
// Requires proof that ElGamal key is valid
let pubkey_validity_proof = PubkeyValidityProofData::new(&elgamal_keypair)?;

let configure_ix = configure_account(
    &spl_token_2022::id(),
    &token_account_pubkey,
    &mint_pubkey,
    decryptable_zero_balance, // AES-encrypted zero
    maximum_pending_balance_credit_counter,
    &owner_pubkey,
    &[],
    ProofLocation::InstructionOffset(
        ProofInstructionOffset::try_from(-1)?, // Proof in previous ix
        &pubkey_validity_proof
    ),
)?;

// Step 5: If manual approval required, mint authority must approve
let approve_ix = if !auto_approve_new_accounts {
    Some(approve_account(
        &spl_token_2022::id(),
        &token_account_pubkey,
        &mint_pubkey,
        &mint_authority,
        &[],
    )?)
} else {
    None
};
```

**Key Requirements**:
- Must provide **PubkeyValidity proof** to prove ElGamal key is valid
- **Decryptable balance** initialized to encrypted zero (using AES key)
- Manual approval may be required depending on mint configuration

## Confidential Transfer Instructions

### Instruction Flow at Program Level

```
┌─────────────────────────────────────────────────────────────┐
│           CONFIDENTIAL TRANSFER INSTRUCTION FLOW            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. DEPOSIT (Public → Pending)                             │
│     ├─ Instruction: ConfidentialTransferInstruction::Deposit│
│     ├─ Accounts: [token_account, mint, authority]          │
│     ├─ Data: amount (u64), decimals (u8)                   │
│     └─ Effect: amount ↓ public, amount ↑ pending (encrypted)│
│                                                             │
│  2. APPLY PENDING BALANCE (Pending → Available)            │
│     ├─ Instruction: ApplyPendingBalance                    │
│     ├─ Accounts: [token_account, authority]                │
│     ├─ Data: expected_pending_balance_credit_counter       │
│     │          new_decryptable_available_balance (AES)     │
│     └─ Effect: pending → available, counter reset          │
│                                                             │
│  3. TRANSFER (Available → Recipient Pending)               │
│     ├─ Instruction: Transfer                               │
│     ├─ Accounts: [source, mint, destination, authority,    │
│     │             equality_proof*, validity_proof*,         │
│     │             range_proof*, zk_elgamal_proof_program]   │
│     ├─ Data: new_source_decryptable_balance (AES)         │
│     ├─ Proofs Required:                                    │
│     │  ├─ Equality: sender amount = receiver amount        │
│     │  ├─ Validity: ciphertexts properly formed            │
│     │  └─ Range: remaining balance ≥ 0                     │
│     └─ Effect: sender available ↓, recipient pending ↑     │
│                                                             │
│  4. WITHDRAW (Available → Public)                          │
│     ├─ Instruction: Withdraw                               │
│     ├─ Accounts: [token_account, mint, authority,          │
│     │             equality_proof*, range_proof*]            │
│     ├─ Data: amount, decimals, new_decryptable_balance    │
│     └─ Effect: available ↓ (encrypted), amount ↑ (public) │
│                                                             │
│  * Proofs verified by ZK ElGamal Proof Program             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Proof Context State Accounts

Large proofs cannot fit in transactions, so they're stored in **context state accounts**:

```
┌─────────────────────────────────────────────────────────────┐
│               CONTEXT STATE ACCOUNT                         │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Owner: ZK ElGamal Proof Program                           │
│         (ZkE1Gama1Proof11111111111111111111111111111)      │
│                                                             │
│  Data Layout:                                               │
│  ├─ context_state_authority: Pubkey (32 bytes)             │
│  │  Who can close this account                             │
│  ├─ proof_type: ProofType (1 byte)                         │
│  │  Which proof this contains                              │
│  └─ proof_data: [u8] (variable)                            │
│     Serialized proof bytes                                  │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Typical Sizes:
├─ BatchedRangeProofU128: 297 bytes
├─ CiphertextCommitmentEquality: 161 bytes
├─ BatchedGroupedCiphertext3HandlesValidity: 227 bytes
└─ PubkeyValidity: 97 bytes
```

**Workflow**:
1. Create context state account (owned by ZK program)
2. Submit proof verification instruction (verifies and stores)
3. Reference context account in transfer instruction
4. Close context account after transfer (reclaim rent)

## ZK ElGamal Proof Program Integration

### Program ID
`ZkE1Gama1Proof11111111111111111111111111111`

### Verification Instructions

| Instruction | Discriminator | Use in Confidential Transfer |
|-------------|---------------|------------------------------|
| **VerifyPubkeyValidity** | `0` | Configure account (prove ElGamal key valid) |
| **VerifyZeroCiphertext** | `1` | Close account (prove balance is zero) |
| **VerifyCiphertextCommitmentEquality** | `2` | Withdraw (prove encrypted = public amount) |
| **VerifyCiphertextCiphertextEquality** | `3` | Transfer equality proof |
| **VerifyBatchedRangeProofU64** | `4` | Not used (too small) |
| **VerifyBatchedRangeProofU128** | `5` | Transfer range proof (balance ≥ 0) |
| **VerifyBatchedRangeProofU256** | `6` | Large amount transfers |
| **VerifyBatchedGroupedCiphertext2HandlesValidity** | `7` | 2-party transfers (no auditor) |
| **VerifyBatchedGroupedCiphertext3HandlesValidity** | `8` | 3-party transfers (with auditor) |
| **VerifyPercentageWithCap** | `9` | Fee calculations |
| **CloseContextState** | `10` | Reclaim rent from proof accounts |

### Proof Verification Flow

```
1. Client generates proof (WASM/Rust)
   ↓
2. Create context state account
   CreateAccount(ZK_ELGAMAL_PROOF_PROGRAM, size)
   ↓
3. Submit verification instruction
   Verify{ProofType}(proof_data)
   ├─ Program validates proof mathematically
   ├─ Stores proof data in context account
   └─ Marks as verified
   ↓
4. Token-2022 instruction references context
   Transfer(..., equality_proof_account, ...)
   ├─ Reads proof data from context account
   ├─ Validates proof matches transfer params
   └─ Executes transfer
   ↓
5. Close context account
   CloseContextState(context_account, destination)
   └─ Reclaims rent
```

## Extension Feature Matrix

### ConfidentialTransferMint

```rust
pub struct ConfidentialTransferMint {
    /// Authority to modify the ConfidentialTransferMint config
    pub authority: OptionalNonZeroPubkey,

    /// Auto-approve new account configurations
    /// If `true`, new accounts can configure without approval
    /// If `false`, authority must call `approve_account`
    pub auto_approve_new_accounts: PodBool,

    /// ElGamal pubkey for auditor (can decrypt all transfers)
    /// Used for compliance in regulated environments
    pub auditor_elgamal_pubkey: OptionalNonZeroElGamalPubkey,
}
```

**Enabled Operations**:
- Configure token accounts for confidential transfers
- Approve/Disable account configurations (if manual approval)
- Update mint authority
- Set auditor key for compliance

### ConfidentialTransferAccount

```rust
pub struct ConfidentialTransferAccount {
    /// Approval status
    pub approved: PodBool,

    /// ElGamal public key for receiving
    pub elgamal_pubkey: ElGamalPubkey,

    /// Pending balance (incoming transfers/deposits)
    pub pending_balance_lo: EncryptedBalance,
    pub pending_balance_hi: EncryptedBalance,

    /// Available balance (ready for transfers)
    pub available_balance: EncryptedBalance,

    /// AES-encrypted available balance (fast decryption)
    pub decryptable_available_balance: DecryptableBalance,

    /// Credit acceptance flags
    pub allow_confidential_credits: PodBool,
    pub allow_non_confidential_credits: PodBool,

    /// Pending balance credit counter (anti-front-running)
    pub pending_balance_credit_counter: PodU64,
    pub maximum_pending_balance_credit_counter: PodU64,
    pub expected_pending_balance_credit_counter: PodU64,
    pub actual_pending_balance_credit_counter: PodU64,
}
```

**Enabled Operations**:
- Deposit (public → pending)
- Apply pending balance (pending → available)
- Transfer (confidential sender → confidential receiver)
- Withdraw (available → public)
- Empty account (for closing)

### ConfidentialTransferFeeConfig

Extends mint to support confidential transfer fees:

```rust
pub struct ConfidentialTransferFeeConfig {
    /// Authority for fee config
    pub authority: OptionalNonZeroPubkey,

    /// ElGamal key for withdraw withheld authority
    /// Allows authority to collect fees confidentially
    pub withdraw_withheld_authority_elgamal_pubkey: ElGamalPubkey,

    /// Whether fees are harvested to mint confidentially
    pub harvest_to_mint_enabled: PodBool,

    /// Withheld fees (encrypted)
    pub withheld_amount: EncryptedWithheldAmount,
}
```

**Enabled Operations**:
- Transfer with encrypted fees
- Harvest fees to mint (confidential)
- Withdraw withheld fees

### ConfidentialMintBurn

Enables private token issuance:

```rust
pub struct ConfidentialMintBurn {
    /// Authority to mint/burn confidentially
    pub authority: OptionalNonZeroPubkey,

    /// Auto-approve new mints
    pub auto_approve_new_accounts: PodBool,

    /// Auditor ElGamal key
    pub auditor_elgamal_pubkey: OptionalNonZeroElGamalPubkey,

    /// Current supply (encrypted)
    pub encrypted_supply: EncryptedBalance,

    /// Decryptable supply for authority
    pub decryptable_supply: DecryptableBalance,
}
```

**Enabled Operations**:
- Mint tokens confidentially (bypasses public supply)
- Burn tokens confidentially
- **Note**: Disables Deposit and Withdraw operations

## Extension Compatibility

### Compatible Combinations

```
✓ ConfidentialTransfer + TransferFee
✓ ConfidentialTransfer + MintCloseAuthority
✓ ConfidentialTransfer + DefaultAccountState
✓ ConfidentialTransfer + MemoTransfer
✓ ConfidentialTransfer + MetadataPointer
✓ ConfidentialTransferFee + TransferFee (both configs active)
✓ ConfidentialMintBurn + ConfidentialTransfer
```

### Incompatible Combinations

```
✗ ConfidentialMintBurn + Deposit/Withdraw
  (MintBurn disables public ↔ confidential conversion)

✗ Adding extensions after mint creation
  (All extensions must be set at initialization)
```

## Account Space Calculation

```rust
use spl_token_2022::extension::{ExtensionType, StateWithExtensions};

// Calculate space for mint with extensions
fn calculate_mint_space(extensions: &[ExtensionType]) -> Result<usize> {
    ExtensionType::try_calculate_account_len::<Mint>(extensions)
}

// Calculate space for account with extensions
fn calculate_account_space(extensions: &[ExtensionType]) -> Result<usize> {
    ExtensionType::try_calculate_account_len::<Account>(extensions)
}

// Example: Mint with ConfidentialTransfer + ConfidentialTransferFee
let mint_extensions = vec![
    ExtensionType::ConfidentialTransferMint,
    ExtensionType::ConfidentialTransferFeeConfig,
];
let mint_space = calculate_mint_space(&mint_extensions)?; // ~188 bytes

// Example: Account with ConfidentialTransfer
let account_extensions = vec![ExtensionType::ConfidentialTransferAccount];
let account_space = calculate_account_space(&account_extensions)?; // ~455 bytes
```

## Resources

### Official Documentation
- [Token-2022 Overview](https://spl.solana.com/token-2022)
- [Confidential Transfer Deep Dive](https://www.solana-program.com/docs/confidential-balances)
- [ZK ElGamal Proof Program Docs](https://docs.anza.xyz/runtime/zk-elgamal-proof)

### Code References
- [ConfidentialTransferMint Extension](https://github.com/solana-program/token-2022/blob/main/program/src/extension/confidential_transfer/mod.rs)
- [ConfidentialTransferAccount Extension](https://github.com/solana-program/token-2022/blob/main/program/src/extension/confidential_transfer/account_info.rs)
- [Extension Type Enum](https://github.com/solana-program/token-2022/blob/main/program/src/extension/mod.rs)
- [ZK Proof Instructions](https://github.com/anza-xyz/agave/blob/master/zk-sdk/src/zk_elgamal_proof_program/instruction.rs)

### Guides
- [QuickNode Token-2022 Confidential Guide](https://www.quicknode.com/guides/solana-development/spl-tokens/token-2022/confidential)
- [Confidential Balances Sample (Rust)](https://github.com/solana-developers/Confidential-Balances-Sample)
- [Confidential Balances Microsite](https://github.com/solana-developers/confidential_balances_microsite)
