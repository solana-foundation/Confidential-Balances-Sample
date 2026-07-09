# Cryptography Reference

Deep dive into the cryptographic primitives powering Solana Confidential Balances.

## Overview

Confidential Balances use three main cryptographic techniques:

| Technique | Purpose | Library |
|-----------|---------|---------|
| **Twisted ElGamal** | Homomorphic encryption of balances | `solana-zk-sdk` |
| **Pedersen Commitments** | Binding commitments for proofs | `solana-zk-sdk` |
| **Sigma Protocols** | Zero-knowledge proofs | `solana-zk-sdk` |

## Twisted ElGamal Encryption

### Why Twisted ElGamal?

Standard ElGamal encrypts messages as group elements, making arithmetic impossible. Twisted ElGamal encrypts the **discrete log** of the message, enabling:

- **Homomorphic addition**: `Enc(a) + Enc(b) = Enc(a + b)`
- **Scalar multiplication**: `k * Enc(a) = Enc(k * a)`

This allows updating encrypted balances without decryption.

### Mathematical Foundation

**Curve**: Curve25519 (Ristretto group)

**Key Generation**:
```
secret_key s ← random scalar
public_key H = s * G    (G is the generator)
```

**Encryption** of message `m`:
```
r ← random scalar (opening)
Commitment C = m * G + r * H_pedersen
Handle      D = r * H

Ciphertext = (C, D)
```

**Decryption**:
```
m * G = C - s * D
m = discrete_log(m * G)
```

### Ciphertext Structure

```
┌─────────────────────────────────────────────────────────────┐
│              ElGamal Ciphertext (64 bytes)                  │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌─────────────────────────┐  ┌─────────────────────────┐   │
│  │  Pedersen Commitment    │  │  Decrypt Handle         │   │
│  │  (32 bytes)             │  │  (32 bytes)             │   │
│  │                         │  │                         │   │
│  │  C = m*G + r*H          │  │  D = r*PK               │   │
│  └─────────────────────────┘  └─────────────────────────┘   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Homomorphic Operations

```rust
// Balance update after transfer
let new_sender_balance = current_balance - transfer_amount;
// Operates on encrypted values:
let new_sender_ct = sender_balance_ct - transfer_ct;

// Adding encrypted values
let total_ct = balance1_ct + balance2_ct;
// Decrypts to: balance1 + balance2
```

### Decryption Limitation

Decryption requires solving discrete log: `m * G = ?`

For efficiency, `decrypt_u32` uses a precomputed table for values 0 to 2^32. Values outside this range require expensive computation.

**Practical implication**: Token amounts should fit in 32 bits after decimal adjustment.

## Pedersen Commitments

### Purpose

Pedersen commitments allow:
1. **Hiding**: Commitment reveals nothing about the value
2. **Binding**: Cannot change the committed value later
3. **Homomorphic**: Can add commitments without revealing values

### Construction

```
Generators: G (standard), H (nothing-up-my-sleeve point)

Commit(m, r):
    C = m * G + r * H
    
where:
    m = message (amount)
    r = opening (randomness)
    C = commitment
```

### Properties

| Property | Guarantee |
|----------|-----------|
| **Hiding** | Given C, cannot determine m without r |
| **Binding** | Cannot find (m', r') ≠ (m, r) with same C |
| **Homomorphic** | C(m₁, r₁) + C(m₂, r₂) = C(m₁+m₂, r₁+r₂) |

### Usage in Transfers

```
Transfer amount: 100 tokens

Sender commitment:   C_s = 100*G + r_s*H
Receiver commitment: C_r = 100*G + r_r*H

Proof shows: C_s and C_r commit to same value
(without revealing 100)
```

## Zero-Knowledge Proofs

### Sigma Protocols

All proofs use Sigma protocols (3-move interactive proofs made non-interactive via Fiat-Shamir):

```
┌──────────┐      commitment      ┌──────────┐
│  Prover  │ ──────────────────►  │ Verifier │
│          │                      │          │
│          │ ◄──────────────────  │          │
│          │      challenge       │          │
│          │                      │          │
│          │ ──────────────────►  │          │
│          │      response        │          │
└──────────┘                      └──────────┘

Non-interactive: challenge = Hash(commitment, context)
```

### Proof Types

#### 1. Public Key Validity Proof

**Proves**: Prover knows secret key for a public key

**Use case**: Account configuration (proves encryption key is valid)

**Statement**: "I know `s` such that `H = s * G`"

```
Commitment: R = k * G           (k random)
Challenge:  c = Hash(H, R)
Response:   z = k + c * s

Verify: z * G == R + c * H
```

#### 2. Zero Ciphertext Proof

**Proves**: A ciphertext encrypts zero

**Use case**: Prove account is empty for closing

**Statement**: "Ciphertext (C, D) encrypts 0"

If `m = 0`: `C = r * H_ped` and `D = r * PK`

Prove knowledge of `r` such that both equations hold.

#### 3. Ciphertext-Commitment Equality Proof

**Proves**: ElGamal ciphertext and Pedersen commitment encode same value

**Use case**: Withdrawal proofs (link encrypted balance to public amount)

**Statement**: "C_elgamal encrypts same value as C_pedersen"

#### 4. Ciphertext-Ciphertext Equality Proof

**Proves**: Two ciphertexts encrypt the same value

**Use case**: Transfer proofs (sender deduction = receiver credit)

**Statement**: "Ciphertext₁ and Ciphertext₂ encrypt the same m"

#### 5. Range Proof

**Proves**: Committed value is in range [0, 2^n)

**Use case**: Prevent negative balances (prove balance ≥ 0)

**Implementation**: Bulletproofs-style aggregated range proof

```
Prove: 0 ≤ m < 2^64

Decompose: m = Σ mᵢ * 2^i  where mᵢ ∈ {0, 1}
Prove each bit commitment is 0 or 1
Aggregate into single proof
```

**Bit lengths used**:
- `BatchedRangeProofU64`: 64-bit range
- `BatchedRangeProofU128`: 128-bit range (for batched amounts)
- `BatchedRangeProofU256`: 256-bit range

#### 6. Grouped Ciphertext Validity Proof

**Proves**: Grouped ciphertext correctly encrypts under multiple keys

**Use case**: Transfer with auditor (encrypts amount for sender, receiver, auditor)

**Statement**: "All handles in grouped ciphertext are valid encryptions of same value"

#### 7. Percentage with Cap Proof

**Proves**: Value is X% of base amount, capped at maximum

**Use case**: Fee calculation proofs

**Statement**: "fee = min(base * rate, cap)"

## Proof Sizes

| Proof Type | Approximate Size |
|------------|------------------|
| PubkeyValidity | ~64 bytes |
| ZeroCiphertext | ~96 bytes |
| CiphertextCommitmentEquality | ~128 bytes |
| CiphertextCiphertextEquality | ~192 bytes |
| BatchedRangeProofU64 | ~800 bytes |
| BatchedRangeProofU128 | ~1,400 bytes |
| GroupedCiphertext3HandlesValidity | ~224 bytes |

## Authenticated Encryption (AES)

### Purpose

ElGamal decryption is expensive (discrete log). For efficient balance viewing by account owners, balances are also encrypted with AES.

### Construction

**Algorithm**: AES-GCM-SIV (authenticated encryption with associated data)

**Key derivation**:
```
ae_key = HKDF(signature("AeKey"))
```

**Encryption**:
```
ciphertext = AES-GCM-SIV.Encrypt(ae_key, nonce, balance)
```

### DecryptableAvailableBalance Field

```
┌─────────────────────────────────────────────────────────────┐
│  Token Account Confidential State                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  available_balance:              ElGamal ciphertext         │
│                                  (for homomorphic ops)      │
│                                                             │
│  decryptable_available_balance:  AES ciphertext             │
│                                  (for efficient viewing)    │
│                                                             │
└─────────────────────────────────────────────────────────────┘

Owner decrypts AES version for fast balance display.
Program uses ElGamal version for transfer operations.
```

## Security Properties

### Confidentiality

| Data | Visibility |
|------|------------|
| Transfer amounts | Encrypted (ElGamal) |
| Account balances | Encrypted (ElGamal + AES) |
| Sender/Receiver addresses | Public |
| Transaction timestamps | Public |

### Integrity

- Range proofs prevent negative balances
- Equality proofs ensure conservation (no token creation)
- Validity proofs ensure proper encryption

### Auditability

Optional auditor can decrypt all transfers:
```
Grouped ciphertext encrypts amount under:
1. Sender public key
2. Receiver public key  
3. Auditor public key (optional)

Auditor can decrypt any transfer for compliance.
```

## Computational Costs

| Operation | Relative Cost |
|-----------|---------------|
| Key generation | Low |
| Encryption | Low |
| Decryption (u32) | Medium (table lookup) |
| Decryption (u64) | High (discrete log) |
| Range proof generation | Very High |
| Range proof verification | Medium |
| Equality proof generation | Medium |
| Equality proof verification | Low |

### On-Chain Verification

Proofs are verified by the **ZK ElGamal Proof Program**:
- Program ID: `ZkE1Gama1Proof11111111111111111111111111111`
- Verification is ~10-50x cheaper than generation
- Large proofs stored in context state accounts

## References

- [Twisted ElGamal Notes (Anza)](https://github.com/anza-xyz/agave/blob/master/docs/src/runtime/zk-docs/twisted_elgamal.pdf)
- [SPL Token 2022 Protocol Paper](https://github.com/solana-program/token-2022/blob/main/zk-token-protocol-paper/part1.pdf)
- [Bulletproofs Paper](https://eprint.iacr.org/2017/1066.pdf)
- [Pedersen Commitments](https://en.wikipedia.org/wiki/Commitment_scheme#Pedersen_commitment)
- [Sigma Protocols](https://en.wikipedia.org/wiki/Proof_of_knowledge#Sigma_protocols)
