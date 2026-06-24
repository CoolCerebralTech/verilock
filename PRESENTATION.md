# Verilock — Blockchain Notary System

## Final Year Project Presentation

### Team
- Student: [Your Name]
- Supervisor: [Supervisor Name]
- Date: [Presentation Date]

---

## Problem Statement

Current smart contract wallets (Gnosis Safe) have **no built-in policy enforcement**:
- Anyone with signing keys can execute any transaction
- No spend limits, destination checks, or approval workflows
- Blind signing — signers don't know what they're approving

## Solution: Verilock

A **three-layer security system** that enforces policy on every Safe transaction:

1. **Policy Layer** (Notary): Business rules, risk scoring, human-in-the-loop
2. **Validation Layer** (Guard): On-chain cryptographic verification
3. **Client Layer** (SDK): Token encoding, transaction construction

---

## Architecture

```
User / Agent → Notary (Policy) → Approval Token → Safe → Guard (Validation) → Blockchain
```

### Components

| Component | Tech | Role | Deployed |
|-----------|------|------|----------|
| Guard | Solidity | Block unauthorized transactions | ✅ Base Sepolia |
| Notary | Go | Policy engine, issue signed tokens | ✅ Running |
| SDK | TypeScript | Client library | 🔄 Local |

---

## Key Features

### 1. Policy-Based Approval
- YAML policy defines: agents, spend limits, destinations, purposes
- Hot-reloadable without contract redeployment
- Three-tier routing: auto-approve → notify+vote → human approval

### 2. Non-Transferable Trust
- Approval tokens signed by Notary (EIP-712)
- Guard verifies signature on-chain
- No need to trust the Safe, only the Notary

### 3. melonTest (Base Sepolia)

| Test | Result |
|------|--------|
| Guard blocks tx without token | ✅ PASS |
| Guard allows removal (escape hatch) | ✅ PASS |
| Full end-to-end with token | ✅ PASS |

---

## Demo Outline

### 1. Safe Without Guard
- Show Safe transaction going through normally
- Explain: anyone can drain funds

### 2. Deploy Guard
```bash
forge script Deploy.s.sol --broadcast
```

### 3. Attach Guard to Safe
- Safe UI → Transaction Builder
- Call `setGuard(guard_address)`

### 4. Test Blocking
- Try sending ETH from Safe
- Show: "Simulation Error: Reverted"
- Guard blocks because no approval token

### 5. Get Approval Token
- Call Notary API: `/v1/action-check`
- Show token response (EIP-712 signed)

### 6. Submit With Token
- Encode token into transaction data
- Submit to Safe
- Show: Transaction succeeds!

### 7. Show Escape Hatch
- Remove Guard: `setGuard(address(0))`
- Safe can always remove Guard (no lock-in)

---

## Resources

- **GitHub**: github.com/[username]/verilock
- **Live on Base Sepolia**:
  - Safe: `0xB7D6...7E11`
  - Guard: `0xB519...C140`
  - Notary: `0x98A4...F36c`

Thank you!
