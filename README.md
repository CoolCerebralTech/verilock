# Verilock

**The financial trust layer for AI agents on Base.**

Verilock is a cryptographic notary that sits between every AI agent and every financial action it wants to take. It holds no customer funds. It holds no customer keys. Every transaction must carry a valid policy-approved signature before the blockchain will execute it.

```typescript
import { VerilockSigner } from '@verilock/agent-sdk';

const verilock = await VerilockSigner.create({
  notaryUrl:       'https://your-notary.example.com',
  agentToken:      process.env.AGENT_TOKEN!,
  agentId:         'trading-bot-01',
  safeAddress:     '0xYourGnosisSafe',
  ownerPrivateKey: process.env.OWNER_KEY!,
});

// This line does everything:
// 1. Calls the Notary — evaluates your YAML policy
// 2. Gets a cryptographic Approval Token
// 3. Submits to your Gnosis Safe on Base
// 4. The Guard verifies the signature on-chain
// 5. Transaction executes — or reverts if anything is wrong
const txHash = await verilock.sendTransaction({
  to:        '0xRecipientAddress',
  value:     parseEther('0.1'),
  amountUsd: 200,
  purpose:   'defi_yield_optimization',
});
```

---

## Why Verilock

AI agents are already moving money autonomously. The trust infrastructure around this is nearly nonexistent.

**Without Verilock:**
- Your AI agent holds the private key directly
- One compromised prompt and the wallet drains in seconds
- No audit trail. No spend limits. No human review on large transactions
- Crypto transactions are permanent — no chargebacks, no fraud department

**With Verilock:**
- Your agent never touches the private key
- Every transaction is evaluated against human-written YAML rules before execution
- Spend limits, purpose binding, behavioral anomaly detection — enforced on-chain
- Every decision is logged to an immutable audit trail with a cryptographic proof

---

## How It Works

Verilock has three components that work together:

```
AI Agent
   │
   ▼
┌─────────────────────────────────┐
│  Phase 1: Notary (Go Server)    │  ← Reads your YAML policy
│  POST /v1/action-check          │  ← Signs Approval Token if approved
│  Holds zero customer funds      │  ← Logs every decision to audit trail
└─────────────────────────────────┘
   │  Signed Approval Token
   ▼
┌─────────────────────────────────┐
│  Phase 3: SDK (TypeScript)      │  ← Encodes token into transaction data
│  @verilock/agent-sdk            │  ← Submits to Gnosis Safe on Base
└─────────────────────────────────┘
   │  Transaction + Token
   ▼
┌─────────────────────────────────┐
│  Phase 2: Guard (Solidity)      │  ← Verifies signature on-chain
│  VerilockGuard.sol              │  ← Reverts if no valid token present
│  Attached to your Gnosis Safe   │  ← Cannot be bypassed — blockchain enforced
└─────────────────────────────────┘
   │  Execute or Revert
   ▼
Base Blockchain
```

The Notary is a **Notary, not a Bank**. It holds no customer funds and no customer keys. A breach of the Notary server yields only the policy evaluation logic and the audit log — customer funds remain protected by the Guard running permanently on-chain.

---

## Repository Structure

```
verilock/
├── core/               ← Phase 1: Go Notary server
├── contracts/          ← Phase 2: Solidity Guard contract
├── sdk/                ← Phase 3: TypeScript SDK
├── docs/               ← Documentation
│   ├── quickstart.md
│   ├── policy-reference.md
│   └── architecture.md
└── examples/           ← Working examples you can run
    ├── simple-agent/
    └── defi-agent/
```

---

## Quickstart

**→ See [docs/quickstart.md](docs/quickstart.md) for the full setup guide.**

Short version:

```bash
# 1. Clone
git clone https://github.com/CoolCerebralTech/verilock.git
cd verilock

# 2. Start the Notary
cd core
cp .env.example .env   # fill in your signing key
go run ./cmd/server/main.go

# 3. Install the SDK
cd ../sdk
npm install
```

---

## Policy — Human-Written YAML Rules

The Notary evaluates every transaction against a policy file you write and sign off on:

```yaml
agents:
  - id: "trading-bot-01"
    enabled: true
    spend_limits:
      max_per_transaction_usd: 500
      max_per_day_usd: 5000
      auto_approve_below_usd: 50
      require_human_above_usd: 100
    allowed_destinations:
      - "0xYourWhitelistedContract"
    allowed_purposes:
      - "defi_yield_optimization"
    behavioral_risk_threshold: 0.7
```

Every version of every policy file is stored with a timestamp and the identity of who changed it. When a regulator asks what rules governed a specific decision, Verilock provides the exact policy version active at that moment — cryptographically proven unaltered.

→ See [docs/policy-reference.md](docs/policy-reference.md) for the full policy schema.

---

## Network

Verilock targets **Base** (Coinbase's L2) exclusively.

| Network | Chain ID | Status |
|---------|----------|--------|
| Base Mainnet | 8453 | Phase 5 |
| Base Sepolia (testnet) | 84532 | Active |

---

## Development Status

| Phase | Component | Status |
|-------|-----------|--------|
| Phase 1 | Go Notary server | ✅ Complete |
| Phase 2 | Solidity Guard contract | ✅ Complete |
| Phase 3 | TypeScript SDK | ✅ Complete |
| Phase 4 | Docker deployment | 🔄 In progress |
| Phase 5 | Design partner pilots | ⏳ Planned |

---

## Security

- **The Notary holds no customer funds and no customer keys.** A server breach cannot drain customer wallets.
- **The Guard runs permanently on-chain.** Even if the Notary server is destroyed, the Guard continues protecting the vault.
- **Fail closed by default.** If the policy file is unreadable, if any internal error occurs, or if an agent is unknown — the answer is always NO.
- **Every decision is audited.** Approved and denied — every evaluation is written to an immutable SQLite log before any response is sent.

---

## License

MIT — see [LICENSE](LICENSE)
