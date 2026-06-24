# Verilock Architecture

## Three-Layer Security Model

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              USER / AGENT                                    │
│                         (Trading Bot, Human)                                 │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            TOLLGATE NOTARY                                   │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────┐                        │
│  │   Policy    │  │   Baseline   │  │   Signing   │                        │
│  │   Engine    │  │    Tracker   │  │   Service   │                        │
│  └─────────────┘  └──────────────┘  └─────────────┘                        │
│         │                 │                  │                               │
│         ▼                 ▼                  ▼                               │
│  ┌─────────────────────────────────────────────────────┐                    │
│  │              Approval Token (EIP-712)              │                    │
│  │  Signed by Notary — includes: destination,        │
│  │  amount, chainId, nonce, expiresAt, signature      │
│  └─────────────────────────────────────────────────────┘                    │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              GNOSIS SAFE                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         TOLLGUARD                                   │   │
│  │  ┌─────────────────┐  ┌──────────────┐  ┌──────────────┐        │   │
│  │  │ checkTransaction│  │ _extractToken│  │  _recoverSigner│        │   │
│  │  │   (before)      │  │              │  │              │        │   │
│  │  └─────────────────┘  └──────────────┘  └──────────────┘        │   │
│  │         │                  │                    │                     │   │
│  │         ▼                  ▼                    ▼                     │   │
│  │  ┌─────────────────────────────────────────────────────────────┐     │   │
│  │  │  Rejects: missing token, expired, wrong sig, replayed       │     │   │
│  │  │  Accepts: valid Notary signature, matching tx details       │     │   │
│  │  └─────────────────────────────────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          BLOCKCHAIN (Base Sepolia)                           │
│                          Transaction executes                                 │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Separation of Concerns

| Layer | Responsibility | Runs On |
|-------|--------------|---------|
| **Policy (Notary)** | Business logic, risk scoring, spend limits | Off-chain server |
| **Guard** | Cryptographic verification, replay prevention, expiry checks | On-chain (Solidity) |
| **SDK** | Token encoding, SDK interface | Client-side |

## Key Design Decisions

### Why Separate Notary and Guard?

**Notary (Off-chain)**
- Can access external data (price feeds, risk models)
- Can implement complex policy logic (tiered approvals, cold-start)
- Hot-reloads policy without redeploying contract
- Human-in-the-loop for high-value transactions

**Guard (On-chain)**
- Cannot be bypassed — every tx goes through it
- Trustless verification — only needs Notary's public key
- Replay protection via nonce consumption
- Immutable once deployed

### Token Format

```
[original tx calldata] + [TOKEN_PREFIX 4 bytes] + [ABI-encoded ApprovalToken]
```

Address: 0xB519fBAC8f59392200565BB4448aEcD498C1140c (Base Sepolia)
Notary: 0x98A47f61..ED563
```

## Test Results

### Foundry Tests
- **setGuard to zero address (removal)**: ✅ PASS
- **Normal tx without token**: ✅ BLOCKED
- **Token replay prevention**: ✅ PASS

### Live Tests (Base Sepolia)
- **Guard deployment**: ✅ Success
- **Guard attachment**: ✅ Success
- **Guard removal (escape hatch)**: ✅ Success

## Known Limitations

1. Guard removal requires manual Safe transaction (by design)
2. Token TTL is 60 seconds — must submit quickly after approval
3. Notary must be online for tokens — Guard blocks all tx if Notary is down

## Future Work

- [ ] Multi-chain support (Ethereum, Arbitrum, Optimism)
- [ ] On-chain policy registry (hybrid model)
- [ ] Hardware security module (HSM) for Notary signing
- [ ] Webhook notifications for Tier 2/3 approvals