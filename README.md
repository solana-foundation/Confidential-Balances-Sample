# Confidential Balances Workshop

A comprehensive workshop for understanding and implementing Solana's Confidential Balances feature in Token-2022 (Token Extensions).

## What are Confidential Balances?

Confidential Balances is a set of Token-2022 extensions that enable **privacy on Solana asset transfers**. Instead of all token amounts being visible on-chain, balances and transfer amounts are encrypted using advanced cryptographic techniques.

### Token-2022 Extensions Involved

Confidential Balances uses the **Token-2022 (Token Extensions) program**, which allows modular features to be added to tokens.

| Extension | Extension Type | Applied To | Required | Purpose |
|-----------|----------------|------------|----------|---------|
| **ConfidentialTransferMint** | `ExtensionType(11)` | Mint | Yes | Configures mint-level settings (auditor, authority, auto-approval) |
| **ConfidentialTransferAccount** | `ExtensionType(12)` | Token Account | Yes | Stores encrypted balances and encryption keys |
| **ConfidentialTransferFeeConfig** | `ExtensionType(13)` | Mint | Optional | Enables confidential transfer fee calculation |
| **ConfidentialMintBurn** | `ExtensionType(33)` | Mint | Optional | Allows private token issuance (disables deposit/withdraw) |

**Key Points:**
- Extensions must be initialized **at creation time** (cannot be added later)
- Account space must be allocated to fit extension data
- Token-2022 Program ID: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`

### Privacy Levels

Confidential Balances support varying degrees of configurable privacy:

1. **Disabled** - No confidentiality (standard SPL tokens)
2. **Whitelisted** - Only approved accounts can use confidential transfers
3. **Opt-in** - Users choose to enable confidentiality
5. **Required** - All transfers must be confidential

## Cryptographic Foundations

The privacy is achieved through:

- **Twisted ElGamal Encryption** - Homomorphic encryption enabling arithmetic on encrypted data (Curve25519/Ristretto)
- **AES-GCM-SIV** - Authenticated encryption for efficient balance viewing by account owners
- **Pedersen Commitments** - Binding, hiding commitments for zero-knowledge proofs
- **Sigma Protocols (ZKPs)** - Proves validity without revealing amounts

### ZK ElGamal Proof Program

Confidential transfers require zero-knowledge proofs verified by a dedicated Solana program:
- **Program ID**: `ZkE1Gama1Proof11111111111111111111111111111`
- **Purpose**: Verifies equality, range, and validity proofs on-chain
- **Integration**: Token-2022 instructions reference proof context accounts

## Repository Structure

```
.
├── src/                            # Core implementation
│   ├── configure.rs                # Configure accounts for confidential transfers
│   ├── deposit.rs                  # Deposit from public to confidential
│   ├── apply_pending.rs            # Apply pending to available balance
│   ├── withdraw.rs                 # Withdraw from confidential to public
│   ├── transfer.rs                 # Confidential transfer between accounts
│   └── bin/
│       └── demo-server.rs          # HTTP API wrapping the modules (used by the slide-deck demo)
├── examples/
│   ├── run_transfer.rs             # End-to-end transfer with balance display
│   └── get_balances.rs             # Query and decrypt all balance types
├── tests/
│   ├── integration_test.rs         # Integration tests for all operations
│   └── common/                     # Test utilities
├── docs/
│   ├── guides/
│   │   ├── product-guide.md        # High-level product overview
│   │   └── wallet-integration.md   # Guide for wallet developers
│   ├── reference/
│   │   ├── token-extensions.md     # Token-2022 program architecture
│   │   ├── cryptography.md         # Encryption & proof details
│   │   └── rust-deps.md            # Rust crate reference
│   └── FAQ.md                      # Troubleshooting & common issues
└── README.md                       # This file
```

## Key Dependencies

### Rust Crates

```toml
# Solana core via granular crates (no solana-sdk umbrella). solana-client 4.3
# is the stable line that sends v1 transactions; solana-message 4.6 carries the
# v1 module (TransactionConfig in the header, 4096-byte limit).
solana-client = "4.3.0"
solana-pubkey = "4.3"        # = solana_address::Address (provides the pubkey! macro)
solana-keypair = "3.1"
solana-signer = "3.0"
solana-signature = "3.5"
solana-transaction = { version = "4.3", features = ["wincode"] }
solana-message = "4.6"
solana-instruction = "3.5"
solana-native-token = "3.0"
solana-zk-sdk = "7.0.1"
solana-system-interface = "3.2.0"

# SPL Token-2022. Single transfers, withdraws, and configures carry their
# proofs inline via ProofLocation::InstructionOffset.
spl-token-2022 = "11.0.0"
spl-associated-token-account = "8.0.0"
spl-token-confidential-transfer-proof-generation = "0.6.1"
spl-token-confidential-transfer-proof-extraction = "0.6.1"

# ZK ElGamal proof-program helpers, still used by the batch and fee flows
# (create/verify/close context state accounts).
solana-zk-elgamal-proof-interface = "0.1.2"
solana-zk-sdk-pod = "0.1.2"
solana-address = "2.6"
```

> **Version notes.** v1 transactions serialize with `wincode`, not `bincode`;
> `VersionedTransaction::try_new` lives behind `solana-transaction`'s `wincode`
> feature, and `solana-rpc-client 4.3` handles the encoding on send. Everything
> resolves to one `solana-instruction 3.5.x` / `solana-address 2.7.x` stack, so
> `Pubkey == Address` and no conversions are needed. Key derivation uses
> zk-sdk 7's `new_from_signer_legacy`, which is byte-identical to the pre-7
> `new_from_signer` — existing accounts stay decryptable.

The single-transfer, withdraw, and configure flows go out in the **v1
transaction format** (SIMD-0385), which raises the size limit from 1232 to
4096 bytes. That is enough to carry the transfer's three ZK proofs inline as
sibling instructions via `ProofLocation::InstructionOffset`, so those flows
have no proof context state accounts to create, fund, or close. The compute
budget rides in the v1 message header (`TransactionConfig`) — under v1 the
runtime treats unset config bits as 0, so `src/send.rs` always sets the
compute-unit and loaded-accounts-data-size limits explicitly. The batch and
fee flows keep their existing strategies: batches compress the account list
with an Address Lookup Table (v0-only), and the fee flow's U256 range proof
is staged into an spl-record account.

## Quick Start

### Prerequisites

- Solana CLI 2.1.13+ (`solana --version`)
- SPL Token CLI 5.1.0+ (`spl-token --version`)
- Rust 1.97.1+
- A cluster running agave 4.1+ — v1 transactions need it. Devnet and mainnet
  both qualify; an older local `solana-test-validator` does not.

### Running the Example Implementation

This repository includes a complete Rust implementation of all confidential transfer operations:

```bash
# Run all integration tests (against devnet — see note above)
SOLANA_RPC_URL=https://api.devnet.solana.com \
PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo test --test integration_test

# Run a specific test
cargo test test_confidential_transfer_between_accounts -- --nocapture

# Run end-to-end transfer example (shows balance changes throughout)
SOLANA_RPC_URL=https://api.devnet.solana.com \
PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example run_transfer

# Query and display encrypted balances
SOLANA_RPC_URL=https://api.devnet.solana.com \
MINT_ADDRESS=<mint> \
OWNER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example get_balances

# Batched transfers from one sender, all legs in a single atomic v0 tx (option 1)
SOLANA_RPC_URL=https://api.devnet.solana.com \
PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example batch_transfer_atomic

# Batched transfers from one sender, one confirmed tx per leg (option 2)
SOLANA_RPC_URL=https://api.devnet.solana.com \
PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example batch_transfer_pipelined

# Confidential transfer on a mint with transfer fees + permanent delegate
SOLANA_RPC_URL=https://api.devnet.solana.com \
PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example run_transfer_with_fees
```

**Available Operations:**
- `src/configure.rs` - Configure token accounts for confidential transfers
- `src/deposit.rs` - Deposit from public to confidential balance
- `src/apply_pending.rs` - Apply pending balance to available balance
- `src/withdraw.rs` - Withdraw from confidential to public balance
- `src/transfer.rs` - Transfer confidentially between accounts (one v1 tx, proofs inline)
- `src/transfer_with_fee.rs` - Transfer on a mint with confidential transfer fees (5 proofs, record-staged U256 range proof)
- `src/batch_transfer.rs` - Batch multiple transfers from one sender (atomic v0+ALT, or pipelined)

**Examples:**
- `examples/run_transfer.rs` - Complete end-to-end transfer with balance display at each step
- `examples/get_balances.rs` - Query and decrypt all balance types (public, pending, available)
- `examples/batch_transfer_atomic.rs` - N transfers from one sender in a single atomic transaction
- `examples/batch_transfer_pipelined.rs` - N transfers from one sender, one confirmed tx per leg
- `examples/run_transfer_with_fees.rs` - Fee-enabled mint: confidential transfer with fee, fee decryption + harvest, permanent-delegate burn

**Batching from one sender.** Spending is a read-modify-write against the sender's opaque
available-balance ciphertext, so transfers from one account are inherently ordered: each leg's
equality proof binds to the ciphertext the previous leg leaves behind. `batch_transfer` exploits
the fact that the sender holds the secret to compute the whole chain of intermediate ciphertexts
*offline* (ElGamal subtracts homomorphically; each proof exposes the next available-balance
ciphertext), generating every proof up front. `batch_transfer_atomic` then pre-verifies all proofs
into context state accounts and lands every `Transfer` in one v0 transaction (an Address Lookup
Table compresses the account list, a compute-budget bump clears the CU ceiling); in-order execution
makes the chained proofs validate deterministically. `batch_transfer_pipelined` submits one confirmed
transaction per leg instead, trading latency for unbounded fan-out past the single-tx size/CU limit.

**Transfers with fees.** A mint carrying `TransferFeeConfig` + `ConfidentialTransferFeeConfig`
withholds a fee on every confidential transfer, encrypted on the recipient account under the
mint's withdraw-withheld authority ElGamal key. The fee-aware transfer needs five proofs instead
of three (equality, transfer-amount validity, percentage-with-cap, fee validity, and a U256 range
proof). The U256 range proof's verify instruction alone exceeds the 1232-byte transaction limit,
so `transfer_with_fee.rs` stages its bytes into an spl-record account across multiple writes and
verifies from there. `run_transfer_with_fees` demonstrates the full loop — transfer, decrypting
the withheld fee, harvesting it to the mint — plus a `PermanentDelegate` burning from the
recipient's account without their signature.

All operations are tested in `tests/integration_test.rs` with complete end-to-end flows.

### Try it with CLI

```bash
# Run the official confidential transfer example script
curl -sSf https://raw.githubusercontent.com/solana-program/token-2022/main/clients/cli/examples/confidential-transfer.sh | bash
```

### Demo server (for the zkproof8 slide deck)

The `demo-server` binary wraps the modules above in a small HTTP API so a webapp
deck can drive a live confidential transfer on stage. Single-tenant, in-memory,
all keypairs in `.env`.

It's the backend for the **zkproof8 talk** slide deck:
[gitteri/zkproof8-talk](https://github.com/gitteri/zkproof8-talk/) — the
webapp there calls these endpoints to drive the live transfer.

**One-time setup:**

```bash
# Generate a fresh .env with five keypairs (PAYER / MINT / SENDER / RECEIVER / AUDITOR)
cargo run --bin demo-server -- generate-env > .env

# The output prints PAYER pubkey to stderr — fund it.
solana airdrop 5 <PAYER_PUBKEY> --url https://api.devnet.solana.com
```

**Run the server:**

```bash
cargo run --bin demo-server
# listens on http://localhost:8088
```

**Endpoints:**

| Method | Path                  | Body                              | Notes                                                        |
| ------ | --------------------- | --------------------------------- | ------------------------------------------------------------ |
| GET    | `/demo/health`        |                                   | `{ ok, validator_reachable, mint, port, rpc_url }`           |
| GET    | `/demo/state`         |                                   | full ledger snapshot for the four-column slide               |
| POST   | `/demo/init`          |                                   | idempotent: mint if missing, configure ATAs, top up sender   |
| POST   | `/demo/transfer`      | `{ "amount_ui": 250000 }` opt.    | runs the full confidential transfer flow                     |
| POST   | `/demo/apply-pending` | `{ "account": "sender"\|"receiver" }` | moves pending balance to available                       |

`SOLANA_RPC_URL` selects devnet or local (`surfpool`, etc). All demo state
resets when keypairs in `.env` are rotated; soft reset on devnet just re-runs
`/demo/init`.

## Core Operations Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    CONFIDENTIAL TRANSFER FLOW               │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Sender                                     Recipient       │
│    │                                           │            │
│    │  1. Deposit (public → pending)            │            │
│    │  ──────────────────────────►              │            │
│    │                                           │            │
│    │  2. Apply (pending → available)           │            │
│    │  ──────────────────────────►              │            │
│    │                                           │            │
│    │  3. Transfer (with ZK proofs)             │            │
│    │  ─────────────────────────────────────────►            │
│    │                                           │            │
│    │                              4. Apply     │            │
│    │                              (pending →   │            │
│    │                               available)  │            │
│    │                                           │            │
│    │                              5. Withdraw  │            │
│    │                              (available → │            │
│    │                               public)     │            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

## Key Concepts

### Balance Types

| Balance Type | Visibility | Purpose |
|--------------|------------|---------|
| **Public** | Visible on-chain | Standard SPL token balance |
| **Pending** | Encrypted | Incoming transfers waiting to be applied |
| **Available** | Encrypted | Usable confidential balance for transfers |

### Encryption Keys

Each confidential token account has two encryption keys derived from the owner's signature:

1. **ElGamal Keypair** - Used for transfer encryption (derived from signing `"ElGamalSecretKey"`)
2. **AES Key** - Used for balance decryption (derived from signing `"AeKey"`)

### ZK Proofs Required for Transfers

| Proof Type | Purpose | Size |
|------------|---------|------|
| **Equality Proof** | Proves two ciphertexts encrypt the same value | Small |
| **Ciphertext Validity** | Proves ciphertexts are properly generated | Small |
| **Range Proof** | Proves value is in range [0, u64::MAX] | Large |

**Inline proofs, one transaction**: a confidential transfer is a single v1
transaction. The three proofs travel as sibling `VerifyProof` instructions
right after the transfer instruction, referenced via
`ProofLocation::InstructionOffset` (offsets 1/2/3, enforced by the
spl-token-2022 `transfer` builder). The whole transaction is ~2.5 KB of the
4096-byte v1 budget and ~238k CU, mostly the range proof's 200k. Withdraw
works the same way (equality + range-U64 inline, one transaction), and
`configure_account` carries its pubkey-validity proof inline too. Signers are
just the fee payer and the token-account authority — no throwaway proof
account keypairs, no rent round-trips.

**Proof context state accounts** remain the mechanism for flows whose proofs
exceed even the v1 budget: the batch flow pre-verifies every leg's proofs into
context state accounts so N transfers fit in one v0 transaction, and the fee
flow stages its U256 range proof through an spl-record account.

## Resources

### Official Documentation

- [Solana Program: Confidential Balances](https://www.solana-program.com/docs/confidential-balances) - Comprehensive guide
- [Anza: ZK ElGamal Proof Program](https://docs.anza.xyz/runtime/zk-elgamal-proof) - Proof verification details
- [SPL Token Confidential Transfer Overview](https://spl.solana.com/confidential-token/deep-dive/overview) - Protocol overview
- [Token CLI Quickstart](https://spl.solana.com/confidential-token/quickstart) - Get started with CLI

### Guides & Tutorials

- [QuickNode: Token-2022 Confidential Guide](https://www.quicknode.com/guides/solana-development/spl-tokens/token-2022/confidential) - Step-by-step implementation
- [Token-2022 Program Documentation](https://spl.solana.com/token-2022) - Extension system overview

### Code Repositories

- [Token-2022 Program](https://github.com/solana-program/token-2022) - Main program source
- [ZK ElGamal Proof Program](https://github.com/solana-program/zk-elgamal-proof) - Proof verification program
  - [JS Client](https://github.com/solana-program/zk-elgamal-proof/tree/main/clients/js) - Full JavaScript client
  - [WASM SDK](https://github.com/solana-program/zk-elgamal-proof/tree/main/zk-sdk-wasm-js) - Browser-compatible crypto
- [Confidential Balances Sample](https://github.com/solana-developers/Confidential-Balances-Sample) - Rust implementation examples
- [Confidential Balances Microsite](https://github.com/solana-developers/confidential_balances_microsite) - Interactive web example

### Sample Transactions (Devnet)

- [Complete Transfer Flow](https://explorer.solana.com/tx/2rhcbfkr64koHWjoHCJKjbxxS6TonbRH1KVQUvZSFJwM7vnz181eb4eqSkgo3aEFmbnZT5K4z124jW2rRXGuAYU2?cluster=devnet)
- [Deposit Transaction](https://explorer.solana.com/tx/wJw7HhX1p737XNvVwJLEwE7oCDuSxyJYZPD7xJqLWL4ao3osJ7bdmUoy8R5pTtfL2EqPysr8v2wgJRNTMM9VHsM?cluster=devnet)
- [Apply Pending Balance](https://explorer.solana.com/tx/6y1aNHz7NzVzbEXxf4Rw5xV1EZ8CWFx1zamL9N49YkdJ3JKRpMSLVqdSGfBobSbiAj5zuxfyibwTC1NXgKdjWco?cluster=devnet)

## Documentation

### Guides
1. **[Product Guide](docs/guides/product-guide.md)** - Understanding the product from a high level
2. **[Wallet Integration](docs/guides/wallet-integration.md)** - Integration patterns for wallet developers

### Technical Reference
3. **[Token Extensions Architecture](docs/reference/token-extensions.md)** - Token-2022 program-level details
4. **[Cryptography Reference](docs/reference/cryptography.md)** - Deep dive into the crypto primitives
5. **[Rust Dependencies](docs/reference/rust-deps.md)** - Using the Rust crates
6. **[JS/WASM Clients](docs/reference/js-clients.md)** - JavaScript and WASM SDK reference

### Troubleshooting
7. **[FAQ & Troubleshooting](docs/FAQ.md)** - Common issues and solutions

## License

This workshop material is provided for educational purposes.
