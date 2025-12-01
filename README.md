

# Identity Bridge Smart Contract Architecture

## Complete Contract Descriptions

---

## 1. CredentialAnchor.sol

**Purpose**: Privacy-preserving credential commitment registry that serves as the source of truth for all credential lifecycle events.

### What It Does

`CredentialAnchor` is the foundational contract that stores **cryptographic commitments** (hashes) of credentials without ever touching Personally Identifiable Information (PII). It acts as an immutable timestamped record of credential issuance, revocation, and updates.

### How It Works

#### Core Data Structure
```solidity
struct CredentialCommit {
    bool published;              // Credential exists
    bool revoked;               // Credential has been revoked
    address issuer;             // Who issued this credential
    uint256 publishedAt;        // When it was published
    uint256 revokedAt;          // When it was revoked (0 if not revoked)
    uint256 expiry;             // Optional expiry timestamp (0 = never expires)
    bytes32 zkVerifyAttestationId; // Optional zkVerify proof aggregation ID
}
```

#### Key Functions

**Publishing Credentials**
- **`publishCommit(bytes32 credentialHash, uint256 expiry)`**
  - Issuer publishes a commitment (hash) of a credential
  - Can optionally set an expiration timestamp
  - Only the issuer can later revoke or update this credential
  - Emits: `CommitPublished`

**Revoking Credentials**
- **`revokeCommit(bytes32 credentialHash)`**
  - Only the original issuer can revoke
  - Permanent action - cannot be undone
  - Emits: `CommitRevoked`

**Updating/Rotating Credentials**
- **`updateCommit(bytes32 oldHash, bytes32 newHash, uint256 expiry)`**
  - Atomically revokes old credential and publishes new one
  - **Protected by 7-day grace period** - issuer cannot update immediately after publishing (protects holders)
  - Emits: `CommitRevoked` and `CommitUpdated`

**Validation**
- **`isValid(bytes32 credentialHash)`**
  - Returns true only if:
    - Published ✓
    - Not revoked ✓
    - Not expired ✓
  - Used by other contracts to verify credential status

**zkVerify Integration**
- **`setZkVerifyAttestationId(bytes32 credentialHash, bytes32 attestationId)`**
  - Links a credential to a zkVerify proof aggregation
  - Can only be set once (immutable after set)
  - Provides additional proof that credential was validated

#### Security Features

| Feature | Protection |
|---------|-----------|
| **7-Day Grace Period** | Prevents issuers from immediately updating credentials after issuance |
| **Single Attestation** | zkVerify attestation ID can only be set once, preventing replacement attacks |
| **Expiry Validation** | Enforces `>=` check for precise expiry handling |
| **Issuer-Only Actions** | Only the original issuer can revoke or update their credentials |

---

## 2. CredentialVerifier.sol

**Purpose**: Cross-chain credential verification system that enables credentials anchored on one blockchain to be verified and used on another chain.

### What It Does

`CredentialVerifier` acts as a **bridge relay** that accepts cryptographic proofs from trusted verifiers (backend/relayers) confirming that a credential exists and is valid on an origin chain. This enables cross-chain credential portability without moving the actual credential data.

### How It Works

#### Core Data Structure
```solidity
struct VerificationResult {
    bool verified;              // Credential has been verified
    uint256 verifiedAt;        // Timestamp of verification
    bytes32 credentialHash;    // Hash of the verified credential
    address originChainAnchor; // Anchor contract address on origin chain
    uint256 originChainId;     // Chain ID where credential was anchored
}
```

#### Key Functions

**Verification**
- **`verifyCredential(bytes32 credentialHash, uint256 originChainId, address originChainAnchor, bytes calldata proof)`**
  - Called by trusted verifier (backend relayer)
  - Validates proof (MVP mode: accepts non-empty proof with expiry check)
  - Creates verification record with composite key: `keccak256(credentialHash, originChainId)`
  - **Composite key prevents cross-chain replay attacks** - same credential on different chains requires separate verification
  - Emits: `CredentialVerified`

**Batch Verification**
- **`batchVerifyCredentials(...)`**
  - Verify up to 50 credentials in a single transaction
  - **Pre-validates ALL inputs** before any state changes (prevents gas bombs)
  - Skips already-verified credentials silently
  - Returns count of newly verified credentials
  - Emits: `CredentialVerified` for each new verification

**Query Functions**
- **`isVerified(bytes32 credentialHash, uint256 originChainId)`**
  - Check if a specific credential has been verified from a specific chain
  - Returns boolean

- **`getVerification(bytes32 credentialHash, uint256 originChainId)`**
  - Returns full verification details including timestamp and origin chain info

**Access Control**
- **`addVerifier(address verifier)`**
  - Owner adds trusted backend/relayer
  
- **`scheduleVerifierRemoval(address verifier)` + `removeVerifier(address verifier)`**
  - **Two-step removal with 1-day delay** - protects against accidental removal during active operations
  - Must schedule first, wait 1 day, then execute removal

**MVP vs. Production Mode**
- **`mvpMode`**: Currently active - accepts proofs with basic validation for rapid development
- **`mvpModeExpiry`**: After this timestamp, MVP mode becomes invalid
- **`disableMvpMode()`**: Owner can disable MVP mode early to transition to production
- Production mode requires full zkBridge proof validation (not yet implemented)

**Emergency Controls**
- **`pause()` / `unpause()`**
  - Owner can pause all verification operations in an emergency
  - Unpause restores normal operation

**Ownership Transfer**
- **`transferOwnership(address newOwner)` + `acceptOwnership()`**
  - **Two-step process** prevents accidental ownership transfer to wrong address
  - New owner must explicitly accept

#### Security Features

| Feature | Protection |
|---------|-----------|
| **Composite Key** | `keccak256(credentialHash, originChainId)` prevents cross-chain replay attacks |
| **1-Day Removal Delay** | Protects against accidental verifier removal during active operations |
| **Pre-validation in Batch** | Validates all inputs before state changes to prevent gas bombs |
| **Pausable** | Emergency stop mechanism for critical security issues |
| **2-Step Ownership** | Prevents accidental transfer to wrong/inaccessible address |
| **MVP Expiry** | Forces transition to production mode after testing period |

---

## 3. CredentialRegistry.sol

**Purpose**: Associates credential hashes with holder addresses and enables **zero-knowledge proof-based claiming** where holders prove ownership without revealing the actual credential data.

### What It Does

`CredentialRegistry` is the **holder tracking** layer that complements the Anchor contract. While Anchor stores credential commitments, Registry tracks **who owns what** and provides secure claiming mechanisms using Zero-Knowledge Proofs (ZKPs).

### How It Works

#### Core Data Structure
```solidity
struct RegistryEntry {
    bytes32 credentialHash;    // Hash of the credential
    address holder;            // Ethereum address of the credential holder
    address issuer;            // Address of the issuer
    uint256 registeredAt;      // Timestamp of registration
    bool active;               // Registry entry is active
}
```

#### Claiming Mechanisms

The contract supports **4 distinct claiming flows**:

### Flow 1: Direct Claiming (Trusted Registrar)

**`claimCredentialDirect(bytes32 credentialHash, uint256[6] calldata publicSignals, address issuer)`**

- **Access**: `onlyTrustedRegistrar` - typically a backend service
- **Proof Verification**: OFF-CHAIN (registrar pre-validates ZKP)
- **Use Case**: Fast claiming for trusted environments (e.g., institutional systems)
- **Public Signals**:
  ```
  [0] credentialHash      - Must match the hash parameter
  [1] holderAddress       - Extracted and used for registration
  [2] isPublished         - Must be 1
  [3] isRevoked          - Must be 0
  [4] currentTimestamp   - Used for expiry check
  [5] expiry             - 0 = no expiry
  ```
- **Validations**:
  - ✓ Not already registered
  - ✓ Credential exists on Anchor
  - ✓ Not revoked
  - ✓ Not expired
  - ✓ Holder hasn't exceeded credential limit (1000 max)
- **Double-Check**: Calls `anchorContract.isValid()` for defense in depth

### Flow 2: Trustless Claiming (zkVerify Aggregation)

**`claimCredential(bytes32 credentialHash, uint256[6] calldata publicSignals, uint256 aggregationId, uint256 domainId, bytes32[] calldata merklePath, uint256 leafCount, uint256 index, address issuer)`**

- **Access**: PUBLIC - anyone can call (but only holder can succeed)
- **Proof Verification**: ON-CHAIN via zkVerify aggregation proof
- **Use Case**: Decentralized, trustless claiming with maximum security
- **How zkVerify Works**:
  1. Holder generates ZKP proving they know the credential data
  2. Proof is submitted to zkVerify aggregation service
  3. zkVerify creates a Merkle tree of many proofs
  4. Holder gets Merkle path for their proof
  5. Contract verifies the Merkle proof on-chain (cheap!)
  6. This allows efficient verification of thousands of proofs
- **Key Check**: `msg.sender` MUST match holder address in public signals
- **Constructs Leaf**:
  ```solidity
  keccak256(
    PROVING_SYSTEM_ID ||  // "groth16"
    vkey ||               // Verification key hash
    VERSION_HASH ||       // Circuit version
    publicInputsHash      // Hash of all public signals
  )
  ```

### Flow 3: Envelope Claiming with Selective Disclosure (Direct)

**`claimCredentialWithEnvelopeDirect(bytes32 credentialHash, uint256[9] calldata publicSignals)`**

- **Access**: `onlyTrustedRegistrar`
- **Proof Verification**: OFF-CHAIN
- **Use Case**: Privacy-preserving claiming with selective disclosure of credential fields
- **Public Signals**:
  ```
  [0] credentialHash           - Poseidon hash of credential data
  [1] holderAddress           - Extracted for registration
  [2] secretCommitment        - Hash published by issuer (not credential hash!)
  [3] currentTimestamp        - Proof generation time
  [4] disclosedCourseName     - Publicly visible if disclosed
  [5] disclosedInstitution    - Publicly visible if disclosed
  [6] disclosedCompletionDate - Publicly visible if disclosed
  [7] disclosedIssuanceDate   - Publicly visible if disclosed
  [8] disclosureFlags         - Bitflags indicating which fields are disclosed
  ```
- **Key Difference**: Anchor stores `secretCommitment` (not credential hash!)
  - `secretCommitment = keccak256(abi.encode(secret, holderAddress))`
  - Issuer publishes secretCommitment to Anchor
  - Issuer shares "envelope" (credential + secret) off-chain with holder
  - Holder proves knowledge of both credential and secret
  - Prevents issuer from knowing holder's address in advance
- **Replay Protection**: `usedSecretCommitments` mapping prevents same envelope from being claimed twice

### Flow 4: Envelope Claiming with Selective Disclosure (zkVerify Aggregation)

**`claimCredentialWithEnvelope(bytes32 credentialHash, uint256[9] calldata publicSignals, ...zkVerify params)`**

- **Access**: PUBLIC
- **Proof Verification**: ON-CHAIN via zkVerify
- **Use Case**: Fully trustless envelope claiming with selective disclosure
- **Same as Flow 3** but with on-chain proof verification via zkVerify aggregation

#### Additional Functions

**Registration (Issuer/Backend)**
- **`registerCredential(bytes32 credentialHash, address holder, address issuer)`**
  - Direct registration by trusted registrar
  - Can be used by backend services that don't require ZKP claiming

**Batch Registration**
- **`batchRegisterCredentials(...)`**
  - Register up to 100 credentials at once
  - Gas-efficient for bulk operations

**Unregistration**
- **`unregisterCredential(bytes32 credentialHash)`**
  - Holder can remove their credential from registry
  - Doesn't affect Anchor (credential still exists)

**Queries**
- **`isRegistered(bytes32 credentialHash)`** - Check if credential is in registry
- **`getHolder(bytes32 credentialHash)`** - Get holder address
- **`getCredentials(address holder)`** - Get all credentials for a holder
- **`getCredentialCount(address holder)`** - Count of holder's credentials

#### Security Features

| Feature | Protection |
|---------|-----------|
| **Rate Limiting** | 1000 credentials max per holder prevents spam |
| **Batch Limits** | 100 credentials max per batch prevents gas bombs |
| **Replay Protection** | `usedSecretCommitments` prevents envelope reuse |
| **Defense in Depth** | Double-checks Anchor contract even after ZKP validation |
| **Holder Extraction** | Direct flows extract holder from `publicSignals[1]`, validated by ZKP |
| **Low-Level Call Validation** | Checks return data length and success for all Anchor calls |
| **Zero Address Check** | Validates issuer is not zero address |

---

## User Flows

### 🔵 Issuer Perspective: Publishing a Credential

#### Standard Flow (No Envelope)

```
1. CREATE CREDENTIAL
   - Issuer creates credential data for holder (e.g., degree certificate)
   - Data includes: holderAddress, courseName, institution, completionDate, etc.

2. HASH CREDENTIAL
   - Generate credentialHash = keccak256(credential data)
   - This hash will be publicly visible on-chain

3. PUBLISH TO ANCHOR
   - Call: anchor.publishCommit(credentialHash, expiry)
   - Credential is now publicly anchored on blockchain
   - Anyone can verify it exists, but cannot see the underlying data

4. SHARE CREDENTIAL OFF-CHAIN
   - Send credential data to holder via secure channel
   - Holder will use this data to generate ZKP

5. (Optional) TRUSTED REGISTRATION
   - If using trusted registrar mode:
   - Backend generates ZKP proving credential validity
   - Backend calls: registry.claimCredentialDirect(...)
   - Holder's address is now linked to credential on-chain
```

#### Envelope Flow (Privacy-Enhanced)

```
1. CREATE CREDENTIAL + SECRET
   - Issuer creates credential data
   - Generate random secret (e.g., 32 bytes)
   - Calculate: secretCommitment = keccak256(abi.encode(secret, holderAddress))

2. PUBLISH SECRET COMMITMENT TO ANCHOR
   - Call: anchor.publishCommit(secretCommitment, expiry)
   - NOTE: Publishing secretCommitment, NOT credentialHash!
   - Issuer cannot correlate this to holder's on-chain activity

3. SHARE ENVELOPE OFF-CHAIN
   - Send "envelope" to holder containing:
     - Full credential data
     - Secret value
     - secretCommitment (for reference)

4. HOLDER CLAIMS (see holder flow below)
   - Issuer has no visibility into when/if holder claims
   - Maximum privacy for holder
```

#### Post-Issuance Management

```
REVOKE
- Call: anchor.revokeCommit(credentialHash)
- Immediately invalidates credential
- Permanent - cannot be undone
- Use case: Holder violated terms, credential was fraudulent

UPDATE/ROTATE
- Wait 7 days after publishing (grace period)
- Call: anchor.updateCommit(oldHash, newHash, newExpiry)
- Atomically revokes old and publishes new
- Use case: Credential data changed, reissue required

LINK ZKVERIFY ATTESTATION
- After submitting proof to zkVerify aggregation
- Call: anchor.setZkVerifyAttestationId(credentialHash, attestationId)
- Can only be set once
- Provides proof that credential was verified by zkVerify
```

---

### 🟢 Holder Perspective: Claiming a Credential

#### Standard Claiming Flow (zkVerify Aggregation)

```
1. RECEIVE CREDENTIAL OFF-CHAIN
   - Issuer sends credential data via email, QR code, or secure link
   - Data includes: credentialHash, holderAddress, issuer, courseName, etc.

2. VERIFY CREDENTIAL EXISTS ON ANCHOR
   - Check: anchor.isValid(credentialHash) == true
   - Ensures credential is published, not revoked, not expired

3. GENERATE ZERO-KNOWLEDGE PROOF
   - Use circuit (Groth16) to prove: "I know the credential data"
   - Circuit validates:
     ✓ Credential data hashes to credentialHash
     ✓ I am the holder (my address is in the data)
     ✓ Credential is published on Anchor
     ✓ Credential is not revoked
     ✓ Credential is not expired
   - Generate proof + public signals

4. SUBMIT TO ZKVERIFY AGGREGATION
   - Send proof to zkVerify aggregation service
   - zkVerify batches many proofs into a single Merkle tree
   - Receive: aggregationId, domainId, merklePath, leafCount, index

5. CLAIM ON-CHAIN
   - Call: registry.claimCredential(
       credentialHash,
       publicSignals,  // [credentialHash, myAddress, isPublished, isRevoked, timestamp, expiry]
       aggregationId,
       domainId,
       merklePath,
       leafCount,
       index,
       issuerAddress
     )
   - Contract verifies:
     ✓ Merkle proof is valid in zkVerify aggregation
     ✓ msg.sender matches holder address in public signals
     ✓ Credential exists on Anchor and is valid
   - Credential is now registered to holder's address

6. USE CREDENTIAL
   - Credential is visible in holder's registry
   - DApps can query: registry.getCredentials(holderAddress)
   - Can prove ownership to third parties
```

#### Envelope Claiming Flow with Selective Disclosure (zkVerify)

```
1. RECEIVE ENVELOPE OFF-CHAIN
   - Issuer sends:
     - Credential data
     - Secret value
     - secretCommitment (for verification)

2. VERIFY SECRET COMMITMENT ON ANCHOR
   - Check: anchor.isValid(secretCommitment) == true
   - Confirms issuer published the commitment

3. CHOOSE WHAT TO DISCLOSE
   - Holder decides which fields to make publicly visible:
     - Course name? YES/NO
     - Institution? YES/NO
     - Completion date? YES/NO
     - Issuance date? YES/NO
   - Set disclosureFlags accordingly (e.g., 0b1010 = disclose fields 1 and 3)

4. GENERATE SELECTIVE DISCLOSURE ZKP
   - Use SelectiveDisclosure circuit to prove:
     ✓ I know credential data and secret
     ✓ Credential data hashes to credentialHash (Poseidon)
     ✓ Secret + my address hashes to secretCommitment
     ✓ For disclosed fields: output actual values
     ✓ For hidden fields: output 0
   - Generate proof + public signals with disclosure info

5. SUBMIT TO ZKVERIFY
   - Send proof to zkVerify aggregation service
   - Receive aggregation parameters

6. CLAIM WITH SELECTIVE DISCLOSURE
   - Call: registry.claimCredentialWithEnvelope(
       credentialHash,
       publicSignals,  // Includes disclosed field values
       aggregationId,
       domainId,
       merklePath,
       leafCount,
       index
     )
   - Contract verifies:
     ✓ Merkle proof is valid
     ✓ msg.sender matches holder address
     ✓ secretCommitment exists on Anchor
     ✓ secretCommitment hasn't been used before
   - Event emitted includes disclosed fields (publicly visible)
   - Hidden fields remain zero/private

7. PRIVACY OUTCOME
   ✓ Issuer never learns holder's on-chain address
   ✓ Public sees only disclosed fields (e.g., "degree from MIT")
   ✓ Hidden fields stay private (e.g., GPA, completion date)
   ✓ Holder controls disclosure at claim time
```

#### Query Your Credentials

```
VIEW CREDENTIALS
- Call: registry.getCredentials(myAddress)
- Returns array of all credentialHashes owned by holder

CHECK CREDENTIAL STATUS
- Call: anchor.getCommit(credentialHash)
- Returns: published, revoked, issuer, timestamps, expiry

UNREGISTER (if desired)
- Call: registry.unregisterCredential(credentialHash)
- Removes from registry (but stays on Anchor)
- Holder can re-claim later if needed
```

#### Cross-Chain Usage

```
USE CREDENTIAL ON ANOTHER CHAIN
- Scenario: Credential issued on Ethereum, want to use on Polygon

1. Backend verifier monitors origin chain (Ethereum)
   - Detects: credential exists and is valid on Ethereum Anchor

2. Backend generates zkBridge proof
   - Proves: "This credential exists on Ethereum Anchor"

3. Backend calls Polygon CredentialVerifier
   - Call: verify.verifyCredential(
       credentialHash,
       originChainId: 1,  // Ethereum mainnet
       originChainAnchor: 0x...,  // Ethereum Anchor address
       proof
     )
   - Credential is now verified on Polygon

4. Holder can use credential on Polygon
   - DApps on Polygon can check:
     verify.isVerified(credentialHash, 1)
   - Returns true = credential exists on Ethereum and is valid
```

---

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────┐
│                        ISSUER                                │
│  Creates credential → Publishes hash to Anchor → Sends to   │
│                      holder off-chain                        │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │  CredentialAnchor.sol │ ◄──── Source of Truth
         │  (Blockchain Chain A) │       - Published commitments
         │                       │       - Revocation status
         │  - publishCommit()    │       - Expiry timestamps
         │  - revokeCommit()     │
         │  - isValid()          │
         └───────┬───────────────┘
                 │
                 │ Validates against
                 │
         ┌───────▼───────────────────────┐
         │  CredentialRegistry.sol       │ ◄──── Holder Tracking
         │  (Same Chain)                 │       - Who owns what
         │                               │       - ZKP-based claiming
         │  - claimCredential()          │
         │  - claimCredentialWithEnvelope│
         │  - registerCredential()       │
         └───────────────────────────────┘
                 ▲
                 │
                 │ Claims with ZKP
                 │
┌────────────────┴───────────────────────────────────────────┐
│                        HOLDER                               │
│  Receives credential → Generates ZKP → Claims on-chain →   │
│                      Uses in DApps                          │
└─────────────────────────────────────────────────────────────┘

         Cross-Chain Bridge
                 │
                 ▼
         ┌──────────────────────┐
         │ CredentialVerifier.sol│ ◄──── Cross-Chain Verification
         │  (Blockchain Chain B) │       - Verifies credentials from Chain A
         │                       │       - Trusted relayers
         │ - verifyCredential()  │       - zkBridge proofs
         │ - isVerified()        │
         └───────────────────────┘
                 ▲
                 │
                 │ Queries verification
                 │
         ┌───────┴──────────┐
         │  DApp on Chain B │
         └──────────────────┘
```

### Key Principles

1. **Privacy by Design**: Only hashes on-chain, never PII
2. **Zero-Knowledge Proofs**: Holders prove ownership without revealing data
3. **Selective Disclosure**: Holders choose what to reveal publicly
4. **Cross-Chain Portability**: Credentials issued on one chain work on others
5. **Issuer Control**: Only issuers can revoke/update their credentials
6. **Holder Sovereignty**: Holders control when and how they claim
7. **Trustless Verification**: zkVerify aggregation enables on-chain proof verification
8. **Defense in Depth**: Multiple validation layers prevent attacks
