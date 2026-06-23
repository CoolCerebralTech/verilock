# Deployment Guide

## Testnet Deployment (Base Sepolia)

### Prerequisites

1. [Foundry](https://getfoundry.sh/) installed
2. [Go 1.22+](https://go.dev/) installed
3. Base Sepolia ETH (get from [faucet](https://www.coinbase.com/faucets/base-ethereum-sepolia-faucet))
4. A Gnosis Safe on Base Sepolia (create at [app.safe.global](https://app.safe.global))

### Step 1: Deploy the Guard Contract

```bash
cd contracts
cp .env.example .env
# Edit .env:
#   DEPLOYER_PRIVATE_KEY=0x...         # your deployer private key
#   TOLLGATE_NOTARY_ADDRESS=0x...        # from step 2 below (or use placeholder)
#   SAFE_ADDRESS=0x...                  # your Safe address
#   EXPECTED_CHAIN_ID=84532               # Base Sepolia

export DEPLOYER_PRIVATE_KEY=0x...  # set your key
export TOLLGATE_NOTARY_ADDRESS=0x...  # set after Notary starts
export SAFE_ADDRESS=0x...  # your Safe
export EXPECTED_CHAIN_ID=84532

forge script script/Deploy.s.sol \\
  --rpc-url https://sepolia.base.org \\
  --private-key $DEPLOYER_PRIVATE_KEY \\
  --broadcast
```

**Output:** `Guard address: 0x...`

### Step 2: Start the Notary

```bash
cd core

# Generate keyfiles (only once)
mkdir -p data
# Create data/notary.key (64 hex chars, no 0x prefix)
# Create data/agent.key (64+ hex chars, no 0x prefix)

cp .env.example .env
# Edit .env:
#   TOLLGATE_KEYFILE_PATH=./data/notary.key
#   AGENT_SECRET_KEYFILE_PATH=./data/agent.key
#   CHAIN_ID=84532
#   GUARD_CONTRACT_ADDRESS=0x...  # from step 1
#   SAFE_ADDRESS=0x...              # your Safe

go run ./cmd/server
```

**Output:** `Notary address: 0x...` (copy this)

### Step 3: Update Notary Config with Guard Address

Edit `core/.env`:
```
GUARD_CONTRACT_ADDRESS=0x...  # from step 1
```

Restart Notary:
```bash
# Ctrl+C to stop, then:
go run ./cmd/server
```

### Step 4: Attach Guard to Safe

1. Go to [app.safe.global](https://app.safe.global)
2. Select your Safe
3. **New Transaction** → **Transaction Builder**
4. **Contract Address**: your Safe address (`0x...`)
5. **ABI**: Paste Safe ABI (or use raw data)
6. **Select Method**: `setGuard(address guard)`
7. **guard (address)**: `0x...` (your Guard address from step 1)
8. Click **Add Transaction** → **Create Batch**
9. **Sign** → **Execute**

### Step 5: Test Blocking

Try sending ETH from the Safe without a token:
- Go to Safe → **Send**
- Enter any address and amount
- Click **Continue**

**Expected:** Safe UI shows "Simulation Error: Reverted" — Guard blocks it!

### Step 6: Test with Approval Token

```bash
# Get approval token from Notary
curl -X POST http://localhost:8080/v1/action-check \\
  -H "Authorization: Bearer $DEV_TOKEN" \\
  -H "Content-Type: application/json" \\
  -d '{
    "agent_id": "trading-bot-01",
    "action": "transfer",
    "destination": "0xDESTINATION_ADDRESS",
    "amount_usd": 20,
    "amount_raw": "20000000000000000",
    "purpose": "defi_yield_optimization",
    "chain_id": 84532,
    "nonce": "test-unique-nonce",
    "timestamp": "2026-06-23T12:00:00Z"
  }'
```

**Response:** Approval token (EIP-712 signed)

Encode with SDK and append to transaction data, then submit to Safe.

## Troubleshooting

### "TokenMissing" Error
- No approval token attached to transaction data
- Get token from Notary first

### "SignatureInvalid" Error
- Notary address in Guard doesn't match actual Notary
- Verify `notaryAddress` in Guard matches Notary startup log

### "TokenExpired" Error
- Token TTL is 60 seconds
- Get fresh token just before submitting

### "Cannot estimate gas" in Safe UI
- Usually means transaction will revert
- Check Guard settings and Notary token

## Security Notes

- **Never commit `.env` or `*.key` files**
- **Never share Notary private key**
- **Testnet only** — do not deploy to mainnet without audit

## Production Checklist

- [ ] Multi-sig Safe (not 1-of-1)
- [ ] Notary behind firewall/VPN
- [ ] HSM for signing key
- [ ] Audit by third-party
- [ ] Bug bounty program
- [ ] Insurance coverage