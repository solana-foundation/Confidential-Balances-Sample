# JavaScript & WASM Client Reference

This document covers the JavaScript ecosystem for Solana Confidential Balances.

## Package Overview

| Package | Purpose | Status |
|---------|---------|--------|
| `@solana/zk-sdk` | WASM bindings for proof generation | Published (v0.3.1) |
| `@solana-program/zk-elgamal-proof` | JS client for proof verification | Dev (v0.1.0) |
| `@solana/zk-elgamal-proof` | Legacy JS client | Legacy |

## @solana/zk-sdk (WASM)

The core cryptographic library compiled from Rust to WebAssembly.

### Installation

```bash
npm install @solana/zk-sdk@0.3.1
```

### Build Targets

The package provides three entry points for different environments:

```json
{
  "./node": "./dist/node/index.cjs",      // Node.js
  "./web": "./dist/web/index.js",         // Browser (ESM)
  "./bundler": "./dist/bundler/index.js"  // Vite/Webpack
}
```

### Browser Setup

#### Direct ESM (No Bundler)

```html
<!DOCTYPE html>
<html>
<head>
  <script type="module">
    import init, { ElGamalKeypair } from '@solana/zk-sdk/web';
    
    // MUST initialize WASM first
    await init();
    
    // Now safe to use
    const keypair = new ElGamalKeypair();
    console.log('Public key:', keypair.pubkey().toBytes());
  </script>
</head>
</html>
```

#### Vite Integration

```javascript
// vite.config.js
import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  optimizeDeps: {
    exclude: ['@solana/zk-sdk']  // Don't pre-bundle WASM
  }
});
```

```typescript
// App.tsx
import { ElGamalKeypair } from '@solana/zk-sdk/bundler';

// WASM auto-initialized by bundler
const keypair = new ElGamalKeypair();
```

#### Node.js

```javascript
const { ElGamalKeypair } = require('@solana/zk-sdk/node');

// No init() needed in Node.js
const keypair = new ElGamalKeypair();
```

### Encryption APIs

#### ElGamal Keypair

```typescript
import { ElGamalKeypair, ElGamalPubkey, ElGamalSecretKey } from '@solana/zk-sdk/web';

// Generate random keypair
const keypair = new ElGamalKeypair();

// Access components
const pubkey: ElGamalPubkey = keypair.pubkey();
const secret: ElGamalSecretKey = keypair.secret();

// From existing secret key
const keypairFromSecret = ElGamalKeypair.fromSecretKey(secret);

// Serialization
const pubkeyBytes: Uint8Array = pubkey.toBytes();      // 32 bytes
const secretBytes: Uint8Array = secret.toBytes();     // 32 bytes

// Deserialization
const recoveredPubkey = ElGamalPubkey.fromBytes(new Uint8Array(pubkeyBytes));
const recoveredSecret = ElGamalSecretKey.fromBytes(new Uint8Array(secretBytes));
```

#### Encryption & Decryption

```typescript
// Encrypt amount
const amount: bigint = 1000n;
const ciphertext = pubkey.encryptU64(amount);

// Encrypt with specific opening (for batching)
import { PedersenOpening } from '@solana/zk-sdk/web';
const opening = new PedersenOpening();
const ciphertextWithOpening = pubkey.encryptWith(amount, opening);

// Decrypt
const decrypted: bigint = secret.decrypt(ciphertext);
console.log(decrypted === amount); // true
```

#### Grouped ElGamal (Multi-Recipient)

```typescript
import { 
  GroupedElGamalCiphertext2Handles,
  GroupedElGamalCiphertext3Handles 
} from '@solana/zk-sdk/web';

// Encrypt for 2 recipients
const ct2 = GroupedElGamalCiphertext2Handles.encrypt(
  pubkey1, pubkey2, amount
);

// Encrypt for 3 recipients (sender + receiver + auditor)
const ct3 = GroupedElGamalCiphertext3Handles.encrypt(
  pubkey1, pubkey2, pubkey3, amount
);

// Decrypt with your key (specify your index)
const decrypted = ct2.decrypt(mySecret, 0); // index 0 or 1
```

#### Authenticated Encryption (AES)

```typescript
import { AeKey, AeCiphertext } from '@solana/zk-sdk/web';

// Generate key
const key = new AeKey();  // 16-byte key

// Encrypt
const ciphertext: AeCiphertext = key.encrypt(amount);

// Decrypt
const decrypted = key.decrypt(ciphertext);
```

### Proof Generation

#### Public Key Validity

```typescript
import { PubkeyValidityProofData, ElGamalKeypair } from '@solana/zk-sdk/web';

const keypair = new ElGamalKeypair();
const proof = new PubkeyValidityProofData(keypair);

// Verify locally
proof.verify(); // throws if invalid

// Serialize for on-chain verification
const proofBytes: Uint8Array = proof.toBytes();
```

#### Ciphertext-Ciphertext Equality

```typescript
import { CiphertextCiphertextEqualityProofData } from '@solana/zk-sdk/web';

const proof = new CiphertextCiphertextEqualityProofData(
  firstKeypair,
  secondPubkey,
  firstCiphertext,
  secondCiphertext,
  secondOpening,
  amount
);

proof.verify();
const bytes = proof.toBytes();
```

#### Zero Ciphertext Proof

```typescript
import { ZeroCiphertextProofData } from '@solana/zk-sdk/web';

// Proves a ciphertext encrypts zero
const proof = new ZeroCiphertextProofData(keypair, ciphertext);
proof.verify(); // throws if ciphertext != 0
```

#### Batched Range Proofs

```typescript
import { 
  BatchedRangeProofU64Data,
  BatchedRangeProofU128Data,
  PedersenCommitment,
  PedersenOpening
} from '@solana/zk-sdk/web';

// Create commitments
const opening1 = new PedersenOpening();
const commitment1 = PedersenCommitment.withU64(amount1, opening1);

const opening2 = new PedersenOpening();
const commitment2 = PedersenCommitment.withU64(amount2, opening2);

// Generate range proof
const proof = new BatchedRangeProofU64Data(
  [commitment1, commitment2],          // Commitments
  new BigUint64Array([amount1, amount2]), // Amounts
  new Uint8Array([32, 32]),              // Bit lengths (must sum to 64)
  [opening1, opening2]                    // Openings
);

proof.verify();
```

### Complete Transfer Proof Example

```typescript
import init, {
  ElGamalKeypair,
  ElGamalPubkey,
  PedersenOpening,
  PedersenCommitment,
  CiphertextCiphertextEqualityProofData,
  BatchedGroupedCiphertext3HandlesValidityProofData,
  BatchedRangeProofU128Data
} from '@solana/zk-sdk/web';

async function generateTransferProofs(
  senderKeypair: ElGamalKeypair,
  recipientPubkey: ElGamalPubkey,
  auditorPubkey: ElGamalPubkey,
  transferAmount: bigint,
  currentBalance: bigint
) {
  await init();
  
  const remainingBalance = currentBalance - transferAmount;
  
  // 1. Generate Pedersen commitments
  const transferOpening = new PedersenOpening();
  const transferCommitment = PedersenCommitment.withU64(transferAmount, transferOpening);
  
  const remainingOpening = new PedersenOpening();
  const remainingCommitment = PedersenCommitment.withU64(remainingBalance, remainingOpening);
  
  // 2. Generate Equality Proof
  const equalityProof = new CiphertextCiphertextEqualityProofData(
    senderKeypair,
    recipientPubkey,
    senderCiphertext,
    recipientCiphertext,
    transferOpening,
    transferAmount
  );
  
  // 3. Generate Ciphertext Validity Proof
  const validityProof = new BatchedGroupedCiphertext3HandlesValidityProofData(
    senderKeypair.pubkey(),
    recipientPubkey,
    auditorPubkey,
    transferAmount,
    transferOpening
  );
  
  // 4. Generate Range Proof
  const rangeProof = new BatchedRangeProofU128Data(
    [remainingCommitment, transferCommitment],
    new BigUint64Array([remainingBalance, transferAmount]),
    new Uint8Array([64, 64]),
    [remainingOpening, transferOpening]
  );
  
  return {
    equality: equalityProof.toBytes(),
    validity: validityProof.toBytes(),
    range: rangeProof.toBytes()
  };
}
```

## @solana-program/zk-elgamal-proof (JS Client)

Client for interacting with the on-chain ZK ElGamal Proof program.

### Installation

```bash
# Not yet on npm - build from source
git clone https://github.com/solana-program/zk-elgamal-proof
cd zk-elgamal-proof/clients/js
pnpm install && pnpm build
```

### Dependencies

```json
{
  "@solana-program/system": "^0.10.0",
  "@solana/kit": "^5.0"  // peer dependency
}
```

### Constants

```typescript
import { 
  ZK_ELGAMAL_PROOF_PROGRAM_ADDRESS,
  BATCHED_RANGE_PROOF_CONTEXT_ACCOUNT_SIZE,
  CIPHERTEXT_COMMITMENT_EQUALITY_CONTEXT_ACCOUNT_SIZE,
  // ... other sizes
} from '@solana-program/zk-elgamal-proof';

// Program ID
// ZkE1Gama1Proof11111111111111111111111111111

// Context account sizes (bytes)
// BATCHED_RANGE_PROOF_CONTEXT_ACCOUNT_SIZE = 297
// CIPHERTEXT_COMMITMENT_EQUALITY_CONTEXT_ACCOUNT_SIZE = 161
```

### Verification Functions

All verification functions return `Promise<Instruction[]>`.

#### verifyPubkeyValidity

```typescript
import { verifyPubkeyValidity } from '@solana-program/zk-elgamal-proof';

// Ephemeral verification (no context account)
const ixs = await verifyPubkeyValidity({
  rpc,
  payer,
  proofData: proofBytes,  // Uint8Array
});

// With persistent context account
const ixs = await verifyPubkeyValidity({
  rpc,
  payer,
  proofData: proofBytes,
  contextState: {
    contextAccount: contextKeypair,  // TransactionSigner
    authority: payer.address,
  },
});
```

#### verifyBatchedRangeProofU128

```typescript
import { verifyBatchedRangeProofU128 } from '@solana-program/zk-elgamal-proof';

const ixs = await verifyBatchedRangeProofU128({
  rpc,
  payer,
  proofData: rangeProofBytes,
  contextState: {
    contextAccount: rangeProofAccount,
    authority: payer.address,
  },
});
```

#### verifyCiphertextCommitmentEquality

```typescript
import { verifyCiphertextCommitmentEquality } from '@solana-program/zk-elgamal-proof';

const ixs = await verifyCiphertextCommitmentEquality({
  rpc,
  payer,
  proofData: equalityProofBytes,
  contextState: {
    contextAccount: equalityProofAccount,
    authority: payer.address,
  },
});
```

#### verifyBatchedGroupedCiphertext3HandlesValidity

```typescript
import { verifyBatchedGroupedCiphertext3HandlesValidity } from '@solana-program/zk-elgamal-proof';

const ixs = await verifyBatchedGroupedCiphertext3HandlesValidity({
  rpc,
  payer,
  proofData: validityProofBytes,
  contextState: {
    contextAccount: validityProofAccount,
    authority: payer.address,
  },
});
```

#### closeContextStateProof

```typescript
import { closeContextStateProof } from '@solana-program/zk-elgamal-proof';

const closeIx = closeContextStateProof({
  contextState: contextAccountAddress,
  authority: payer,
  destination: payer.address,  // Rent recipient
});
```

### All Available Verification Functions

```typescript
export {
  verifyZeroCiphertext,
  verifyPubkeyValidity,
  verifyPercentageWithCap,
  verifyBatchedRangeProofU64,
  verifyBatchedRangeProofU128,
  verifyBatchedRangeProofU256,
  verifyCiphertextCiphertextEquality,
  verifyCiphertextCommitmentEquality,
  verifyGroupedCiphertext2HandlesValidity,
  verifyGroupedCiphertext3HandlesValidity,
  verifyBatchedGroupedCiphertext2HandlesValidity,
  verifyBatchedGroupedCiphertext3HandlesValidity,
  closeContextStateProof,
} from '@solana-program/zk-elgamal-proof';
```

## Complete Transfer Example

```typescript
import { createSolanaRpc, generateKeyPairSigner, pipe } from '@solana/kit';
import init, { 
  ElGamalKeypair,
  PubkeyValidityProofData,
  BatchedRangeProofU128Data,
  CiphertextCiphertextEqualityProofData,
  BatchedGroupedCiphertext3HandlesValidityProofData
} from '@solana/zk-sdk/web';
import {
  verifyBatchedRangeProofU128,
  verifyCiphertextCommitmentEquality,
  verifyBatchedGroupedCiphertext3HandlesValidity,
  closeContextStateProof,
} from '@solana-program/zk-elgamal-proof';

async function confidentialTransfer(
  senderKeypair: ElGamalKeypair,
  recipientPubkey: ElGamalPubkey,
  auditorPubkey: ElGamalPubkey | null,
  amount: bigint,
  currentBalance: bigint
) {
  // Initialize WASM
  await init();
  
  const rpc = createSolanaRpc('https://api.devnet.solana.com');
  const payer = await generateKeyPairSigner();
  
  // 1. Generate proofs client-side
  const proofs = await generateTransferProofs(
    senderKeypair,
    recipientPubkey,
    auditorPubkey,
    amount,
    currentBalance
  );
  
  // 2. Create context accounts for proofs
  const rangeProofAccount = await generateKeyPairSigner();
  const equalityProofAccount = await generateKeyPairSigner();
  const validityProofAccount = await generateKeyPairSigner();
  
  // 3. Build verification instructions
  const rangeIxs = await verifyBatchedRangeProofU128({
    rpc,
    payer,
    proofData: proofs.range,
    contextState: {
      contextAccount: rangeProofAccount,
      authority: payer.address,
    },
  });
  
  const equalityIxs = await verifyCiphertextCommitmentEquality({
    rpc,
    payer,
    proofData: proofs.equality,
    contextState: {
      contextAccount: equalityProofAccount,
      authority: payer.address,
    },
  });
  
  const validityIxs = await verifyBatchedGroupedCiphertext3HandlesValidity({
    rpc,
    payer,
    proofData: proofs.validity,
    contextState: {
      contextAccount: validityProofAccount,
      authority: payer.address,
    },
  });
  
  // 4. Build transfer instruction (using spl-token-2022 client)
  const transferIx = buildConfidentialTransferInstruction(
    senderAccount,
    recipientAccount,
    rangeProofAccount.address,
    equalityProofAccount.address,
    validityProofAccount.address,
    // ... other params
  );
  
  // 5. Build cleanup instructions
  const closeIxs = [
    closeContextStateProof({
      contextState: rangeProofAccount.address,
      authority: payer,
      destination: payer.address,
    }),
    closeContextStateProof({
      contextState: equalityProofAccount.address,
      authority: payer,
      destination: payer.address,
    }),
    closeContextStateProof({
      contextState: validityProofAccount.address,
      authority: payer,
      destination: payer.address,
    }),
  ];
  
  // 6. Send transactions
  // TX1: Create context accounts
  // TX2: Range proof verification
  // TX3: Equality + Validity proof verification
  // TX4: Execute transfer
  // TX5: Close context accounts
  
  return { success: true };
}
```

## Browser Considerations

### WASM Initialization

**Always call `init()` before using any `@solana/zk-sdk` functions in browser:**

```typescript
import init from '@solana/zk-sdk/web';

let initialized = false;

async function ensureInitialized() {
  if (!initialized) {
    await init();
    initialized = true;
  }
}

// Call before any crypto operations
await ensureInitialized();
```

### Bundle Size

- **@solana/zk-sdk**: ~8.3 MB (includes WASM binary)
- Use code splitting to lazy-load crypto modules

### Browser Compatibility

Requires:
- WebAssembly support
- ES2015+ (async/await, classes)
- BigInt support
- `window.crypto` for randomness

## Performance Notes

| Operation | WASM vs Native Rust |
|-----------|---------------------|
| Key generation | ~1.5x slower |
| Encryption | ~2x slower |
| Proof generation | ~5-10x slower |
| Proof verification | ~3x slower |

**Recommendations:**
- Generate proofs in background/worker threads
- Cache encryption keys rather than re-deriving
- Pre-compute proofs when possible

## Troubleshooting

### "WASM not initialized"

```typescript
// Always init before use
await init();
```

### "BigInt not supported"

```typescript
// Use BigInt literals
const amount = 1000n;  // Not 1000

// Or explicit conversion
const amount = BigInt(1000);
```

### "Proof verification failed"

- Check that proof data matches expected format
- Verify amounts match between commitments and ciphertexts
- Ensure correct keypairs are used for each party

## Resources

- [@solana/zk-sdk on NPM](https://www.npmjs.com/package/@solana/zk-sdk)
- [zk-elgamal-proof Repository](https://github.com/solana-program/zk-elgamal-proof)
- [WASM Examples](https://github.com/solana-program/zk-elgamal-proof/tree/main/zk-sdk-wasm-js/examples)
