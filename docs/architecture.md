# Architecture

Tollgate is three components that work together. Each has a clearly defined boundary of responsibility and communicates with the others through well-defined interfaces. No component can be bypassed by compromising another.

---

## The Three Components

### Phase 1 — The Notary (Go Server)

**Lives:** Off-chain, on your server  
**Language:** Go  
**Holds:** Zero customer funds, zero customer keys  

The Notary is the policy brain. It receives financial action requests from AI agents, evaluates them against human-written YAML rules, and issues cryptographically signed Approval Tokens when the rules are satisfied.

The Notary holds exactly one sensitive asset: its own ECDSA secp256k1 private key. This key has no access to customer funds. It cannot move money anywhere. Its sole purpose is to produce signatures that the on-chain Guard recognizes as legitimate.

```
Incoming request
      │
      ▼
┌─────────────────────────────────────────────┐
│  Layer 1 — Gateway                          │
│  Rate limiting, request size, auth          │
│  Holds nothing sensitive                    │
├─────────────────────────────────────────────┤
│  Layer 2 — Policy Engine                    │
│  Reads policy.yaml, evaluates 11 checks     │
│  Isolated from internet, holds no keys      │
├─────────────────────────────────────────────┤
│  Layer 3 — Signing Service                  │
│  Signs with ECDSA key, writes audit log     │
│  Never reachable from outside               │
└─────────────────────────────────────────────┘
      │
      ▼
Signed Approval Token (or denial)
```

**Key files:**
```
core/
├── cmd/server/main.go          ← Entry point
├── internal/
│   ├── config/config.go        ← Environment validation
│   ├── policy/engine.go        ← The 11-check evaluation pipeline
│   ├── signing/approval.go     ← EIP-712 token construction
│   ├── audit/log.go            ← Immutable SQLite audit trail
│   └── baseline/scorer.go      ← Behavioral anomaly detection
└── policies/policy.yaml        ← Human-written rules
```

---

### Phase 2 — The Guard (Solidity Smart Contract)

**Lives:** On-chain, permanently  
**Language:** Solidity  
**Network:** Base  

The Guard is a Gnosis Safe module deployed once during onboarding. It attaches to the customer's Safe and enforces one hardcoded law:

> No transaction may leave this vault unless it carries a valid Tollgate signature.

This is what makes bypass physically impossible. The enforcement lives in the blockchain — not in the server. Even if the Notary server is destroyed, the Guard keeps running. Even if the AI agent goes rogue and calls the vault directly, the blockchain rejects the transaction.

**Verification pipeline (in checkTransaction):**
```
1.  msg.sender must be the Safe
2.  Guard must not be paused
3.  Extract ApprovalToken from transaction data
4.  Token must not be expired
5.  Token nonce must not be consumed (replay prevention)
6.  Token chainId must match block.chainid
7.  Token destination must match actual transaction target
8.  Token amountRaw must match actual transaction value
9.  EIP-712 signature must recover to notaryAddress
10. Store nonce for post-execution consumption
11. Emit TransactionApproved event
```

**Key files:**
```
contracts/
├── src/
│   ├── TollgateGuard.sol     ← Main Guard contract
│   ├── TollgateTypes.sol     ← EIP-712 hashing (must match Phase 1)
│   └── interfaces/
│       ├── IGuard.sol        ← Gnosis Safe Guard interface
│       └── ISafe.sol         ← Gnosis Safe interface
└── test/
    └── TollgateGuard.t.sol   ← 22 tests, all must pass
```

---

### Phase 3 — The SDK (TypeScript)

**Lives:** In the developer's codebase  
**Language:** TypeScript  
**Package:** `@tollgate/agent-sdk`  

The SDK hides all the complexity. The developer installs one package and calls one method. The Notary communication, EIP-712 encoding, token injection, and Safe submission all happen invisibly.

```typescript
// Without Tollgate: agent holds the key directly — dangerous
const tx = await wallet.sendTransaction({ to, value });

// With Tollgate: policy enforced, token verified, audit logged
const tx = await tollgate.sendTransaction({ to, value, amountUsd, purpose });
```

**Key files:**
```
sdk/src/
├── index.ts      ← TollgateSigner — what developers import
├── api.ts        ← TollgateClient — HTTP calls to Phase 1
├── encoder.ts    ← injectTollgateToken — calldata encoding
├── types.ts      ← Zod schemas, ABI definition, constants
└── errors.ts     ← Typed error hierarchy
```

---

## How the Components Connect

### The Approval Token — shared truth

The Approval Token is the artifact that connects Phase 1 and Phase 2. It is an EIP-712 structured data object signed by the Notary's ECDSA key. The Guard verifies this signature on-chain using `ecrecover`.

For verification to work, both components must compute identical EIP-712 hashes. This requires:

1. **Identical type string** — the field names, types, and order in `ApprovalToken(bytes32 tokenId,string agentId,...)` must be byte-for-byte identical in Go and Solidity
2. **Identical domain separator** — `name="Tollgate"`, `version="1"`, `chainId`, `verifyingContract` must match
3. **V normalization** — Go's `crypto.Sign()` returns V as 0 or 1. Ethereum's `ecrecover` expects 27 or 28. Both Phase 1 and Phase 2 handle this explicitly.

```
Phase 1 (Go)                          Phase 2 (Solidity)
────────────────                       ──────────────────
keccak256(typeString)        ═══════   keccak256(typeString)
keccak256(domainSeparator)   ═══════   keccak256(domainSeparator)
keccak256(structHash)        ═══════   keccak256(structHash)
keccak256(0x1901 + ...)      ═══════   keccak256(0x1901 + ...)
crypto.Sign(hash, privateKey) ──────►  ecrecover(hash, v, r, s)
                                       recovered == notaryAddress ✓
```

### Token in transaction data

The SDK encodes the token into the Safe transaction's `data` field using a 4-byte prefix:

```
data field = [ original calldata ] + [ 0x544F4C47 ] + [ abi.encode(ApprovalTokenData) ]
```

The Guard scans the `data` field for the prefix `0x544F4C47` (bytes4 of `keccak256("tollgate.approval.v1")`), slices everything after it, and ABI-decodes it as `ApprovalTokenData`.

---

## Security Properties

### The honeypot problem — solved

Traditional key-holding proxies hold customer private keys. A single server breach exposes every customer's funds simultaneously. Tollgate's architecture makes that outcome impossible:

- Customer private keys never enter Tollgate's system
- Tollgate's signing key is financially inert — it cannot authorize a transaction to any destination without the Guard
- A breach of the Notary yields policy logic and audit logs — not funds

### Fail closed

Every error path in every component results in a denial, never an accidental approval:

- Policy file unreadable → deny all requests
- Audit log write failure → deny the transaction (no unrecorded approvals)
- Any internal error → deny
- Unknown agent → deny
- Token missing from transaction → Guard reverts

### On-chain permanence

The Guard runs as long as Base exists. Even if:
- The Notary server is destroyed
- The Notary company ceases to exist
- The developer loses the private key

The Guard continues protecting the vault. No new approvals can be issued — but no existing funds can be moved without one.

---

## EIP-712 Type Definitions (locked)

These definitions are shared between Phase 1 and Phase 2. Changing them requires simultaneous updates to both components and a new Guard deployment.

```
EIP712Domain {
  name:              "Tollgate"
  version:           "1"
  chainId:           uint256  (84532 for Base Sepolia, 8453 for Base Mainnet)
  verifyingContract: address  (deployed Guard address)
}

ApprovalToken {
  tokenId:     bytes32
  agentId:     string
  destination: address
  amountRaw:   uint256
  chainId:     uint256
  nonce:       bytes32
  expiresAt:   uint256
  policyHash:  bytes32
}
```

---

## Audit Trail

Every policy evaluation — approved and denied — is written to an append-only SQLite database before any response is sent. The record includes:

- Agent ID and the request payload
- The exact policy version active at evaluation time (version string + keccak256 hash)
- The behavioral risk score at decision time
- The decision and denial code if applicable
- The token ID if approved
- A timestamp

Cryptographic hashes of the audit log are published externally at regular intervals. Tampering with internal logs is detectable because the external fingerprints will not match.