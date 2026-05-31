# Quickstart — Tollgate in 15 Minutes

This guide gets you from zero to a working protected transaction on Base Sepolia testnet.

**What you need:**
- Go 1.21+
- Node.js 20+
- Foundry (forge, cast, anvil)
- Git

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/CoolCerebralTech/tollgate.git
cd tollgate
```

---

## Step 2 — Start the Notary (Phase 1)

The Notary is the policy brain. It evaluates every transaction request against your YAML rules and issues signed Approval Tokens.

```bash
cd core

# Copy the environment template
cp .env.example .env
```

Generate your signing key and agent secret. Open Git Bash and run:

```bash
# Generate ECDSA secp256k1 signing key
go run keygen.go
```

Copy the output values into `.env`:

```env
TOLLGATE_SIGNING_KEY_HEX=your_64_char_hex_key
AGENT_TOKEN_SECRET=your_64_char_hex_secret
SERVER_PORT=8080
POLICY_FILE_PATH=./policies/policy.yaml
AUDIT_DB_PATH=./data/audit.db
APPROVAL_TOKEN_TTL_SECONDS=60
ENVIRONMENT=development
DRY_RUN_MODE=false
RATE_LIMIT_PER_AGENT_RPS=10
RATE_LIMIT_BURST=20
GLOBAL_RATE_LIMIT_RPS=100
```

Start the Notary:

```bash
go run ./cmd/server/main.go
```

You will see:
```
TOLLGATE NOTARY — CONFIG
  Environment : development
  Port        : 8080
  ...
startup canaries passed
DEV TOKEN (trading-bot-01) — use in Authorization header
Bearer eyJhZ2...

tollgate notary listening  {"address": "[::]:8080"}
```

**Copy the Bearer token** — you will need it in Step 4.

---

## Step 3 — Deploy the Guard (Phase 2)

The Guard is the on-chain enforcer. It attaches to a Gnosis Safe and verifies every transaction carries a valid Tollgate signature.

```bash
cd ../contracts
```

Start a local blockchain in a separate terminal:

```bash
anvil
```

Copy Account 0's private key from the Anvil output. Then deploy:

```bash
# In the contracts/ directory
export DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export TOLLGATE_NOTARY_ADDRESS=0x174394D59b5700b48Bd48B5F06c7B96e8e43b6b5

forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --broadcast
```

Note the deployed Guard address from the output:
```
Guard deployed: 0x5FbDB2315678afecb367f032d93F642f64180aa3
```

Verify it is live:
```bash
cast call 0x5FbDB2315678afecb367f032d93F642f64180aa3 \
  "notaryAddress()(address)" \
  --rpc-url http://127.0.0.1:8545
# Should return your Notary address
```

---

## Step 4 — Use the SDK (Phase 3)

The SDK hides all the complexity. One import, one method.

```bash
cd ../sdk
npm install
```

Create `my-first-agent.ts`:

```typescript
import { TollgateSigner } from '@tollgate/agent-sdk';

async function main() {
  const tollgate = await TollgateSigner.create({
    notaryUrl:       'http://localhost:8080',
    agentToken:      'PASTE_YOUR_BEARER_TOKEN_HERE',
    agentId:         'trading-bot-01',
    safeAddress:     '0xYourGnosisSafeAddress',
    ownerPrivateKey: '0xYourSafeOwnerPrivateKey',
  });

  console.log('Tollgate ready. Sending transaction...');

  // This evaluates policy, gets approval, and submits to the Safe
  const result = await tollgate.simulate({
    to:        '0xdef4560000000000000000000000000000000000',
    value:     10000000n,
    amountUsd: 10.00,
    purpose:   'defi_yield_optimization',
  });

  console.log('Result:', result.status);
  if (result.status === 'approved') {
    console.log('Token ID:', result.approval_token.token_id);
    console.log('Signature:', result.approval_token.signature);
  }
}

main().catch(console.error);
```

Run it:
```bash
npx tsx my-first-agent.ts
```

Expected output:
```
Tollgate ready. Sending transaction...
Result: approved
Token ID: uuid-here
Signature: 0x...
```

---

## What Just Happened

1. The SDK sent your transaction details to the Notary
2. The Notary evaluated them against `policies/policy.yaml`
3. The Notary signed an EIP-712 Approval Token with its ECDSA key
4. The SDK encoded the token into the transaction calldata
5. The Guard on-chain verified the signature before execution

If you change the `purpose` to `buy_nfts` — a purpose not in the policy — you get:
```
TollgateTransactionDeniedError: [PURPOSE_MISMATCH] Purpose "buy_nfts" is not allowed
```

That is the entire product in one line.

---

## Next Steps

- [docs/policy-reference.md](policy-reference.md) — write your own YAML policy
- [docs/architecture.md](architecture.md) — understand how the components connect
- [examples/simple-agent/](../examples/simple-agent/) — a minimal working example
- [examples/defi-agent/](../examples/defi-agent/) — a complete DeFi trading agent