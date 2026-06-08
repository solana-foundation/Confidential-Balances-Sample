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
# Solana core (agave v4). The whole graph is on solana-zk-sdk 6.0.1:
# spl-token-2022 11.0.0 targets it natively, so there is no version boundary
# to cross and no byte-casting.
solana-sdk = "4.0.1"
solana-client = "4.1.0-beta.3"
solana-zk-sdk = "6.0.1"
solana-system-interface = "3.2.0"

# SPL Token-2022 (agave v4 aligned), all on zk-sdk 6.0.1.
spl-token-2022 = "11.0.0"
spl-associated-token-account = "8.0.0"
spl-token-confidential-transfer-proof-generation = "0.6.0"
spl-token-confidential-transfer-proof-extraction = "0.6.0"

# ZK ElGamal proof-program helpers (create/verify/close context state accounts).
solana-zk-elgamal-proof-interface = "0.1.2"
solana-zk-sdk-pod = "0.1.2"
solana-address = "2.6"
```

> **Version note: `solana-client` is pinned to `4.1.0-beta.3` on purpose.**
> `spl-token-2022 = 11.0.0` requires `solana-system-interface 3.2`, which in
> turn needs `solana-instruction >= 3.4`. The only stable client, `solana-client
> 4.0.0`, caps `solana-instruction < 3.4`, so it cannot coexist with token-2022
> 11. `4.1.0-beta.3` is the first published client that lifts that cap, so a beta
> is required for now. Bump this to a stable `solana-client` 4.1 once it ships
> (that is the only change needed to go fully stable).

Confidential transfers run entirely on `solana-zk-sdk 6.0.1`: keys and proofs
are generated with 6.0.1, pre-verified into `ProofContextState` accounts, and
referenced from spl-token-2022's instruction builders via
`ProofLocation::ContextStateAccount`. token-2022 11's account fields and
builders speak the `solana-zk-sdk-pod` POD types directly, so no version
bridging is needed.

(A residual `solana-zk-sdk 4.0` still appears in `Cargo.lock` as transitive
baggage from `spl-pod` and the older `spl-token-2022-interface 2.1.0` pulled by
`spl-associated-token-account` / `solana-account-decoder`. It is off the
confidential-transfer path and harmless; it clears once those crates move to
`spl-token-2022-interface 3.0.0` / zk-sdk 6.0.1 upstream.)

## Quick Start

### Prerequisites

- Solana CLI 2.1.13+ (`solana --version`)
- SPL Token CLI 5.1.0+ (`spl-token --version`)
- Rust 1.70+

### Running the Example Implementation

This repository includes a complete Rust implementation of all confidential transfer operations:

```bash
# Start local test validator
solana-test-validator --quiet --reset &

# Run all integration tests
cargo test --test integration_test

# Run a specific test
cargo test test_confidential_transfer_between_accounts -- --nocapture

# Run end-to-end transfer example (shows balance changes throughout)
SOLANA_RPC_URL=https://zk-edge.surfnet.dev:8899 \
PAYER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example run_transfer

# Query and display encrypted balances
SOLANA_RPC_URL=https://zk-edge.surfnet.dev:8899 \
MINT_ADDRESS=<mint> \
OWNER_KEYPAIR=$(cat ~/.config/solana/id.json) \
cargo run --example get_balances
```

**Available Operations:**
- `src/configure.rs` - Configure token accounts for confidential transfers
- `src/deposit.rs` - Deposit from public to confidential balance
- `src/apply_pending.rs` - Apply pending balance to available balance
- `src/withdraw.rs` - Withdraw from confidential to public balance
- `src/transfer.rs` - Transfer confidentially between accounts (with proof context state accounts)

**Examples:**
- `examples/run_transfer.rs` - Complete end-to-end transfer with balance display at each step
- `examples/get_balances.rs` - Query and decrypt all balance types (public, pending, available)

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

**Proof Context State Accounts**: To avoid transaction size limitations, each
proof is pre-verified into a temporary on-chain account and the transfer
instruction references it via `ProofLocation::ContextStateAccount`. The
implementation in `src/transfer.rs` packs the full flow into **3
transactions**:

1. **Tx 1**: create all three proof accounts (equality / validity / range)
   and verify the **validity** proof.
2. **Tx 2**: verify the **range** proof on its own — ~1006-byte ix, the
   binding constraint on transaction size.
3. **Tx 3**: verify the **equality** proof, run `inner_transfer`, and close
   all three proof accounts to reclaim rent.

The proof accounts use the **payer** (not the sender) as the context-state
authority. This keeps the sender out of the verify txs' `account_keys`,
saving 32 bytes per tx — the difference between fitting and overflowing the
1232-byte legacy tx-size limit on the range-verify tx. The sender still
signs Tx 3 because it's the transfer's token-account authority.

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
