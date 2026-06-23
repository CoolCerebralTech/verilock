# Tollgate — Blockchain Notary System for Gnosis Safe

A three-layer security system that enforces policy-based approval on every transaction leaving a Gnosis Safe.

## Architecture

```
User / Agent → Notary (Policy) → Approval Token → Safe → Guard (Validation) → Transaction Executes
```

| Component | Technology | Role |
|-----------|-----------|------|
| **Guard** | Solidity | On-chain validation — blocks unauthorized transactions |
| **Notary** | Go | Off-chain policy engine — issues signed approval tokens |
| **SDK** | TypeScript | Client library — encodes tokens into transaction data |

## Quick Start

### Prerequisites

- [Go 1.22+](https://go.dev/)
- [Foundry](https://getfoundry.sh/)
- [Node.js 18+](https://nodejs.org/)
- A Gnosis Safe on [Base Sepolia](https://www.base.org/)

### 1. Clone & Setup

```bash
git clone https://github.com/<your-username>/tollgate.git
cd tollgate
```

### 2. Deploy the Guard

```bash
cd contracts
cp .env.example .env
# Edit .env: set your deployer key, Safe address, Notary address

forge script script/Deploy.s.sol \
  --rpc-url base_sepolia \
  --private-key $DEPLOYER_PRIVATE_KEY \
  --broadcast
```

### 3. Attach Guard to Safe

Via Safe UI → Transaction Builder → `setGuard(address)` → Guard address

### 4. Start the Notary

```bash
cd core
cp .env.example .env
# Edit .env: set your keyfiles, Safe address, Guard address

generate_keyfile.sh  # create data/notary.key and data/agent.key
go run ./cmd/setup    # first run
go run ./cmd/server   # start notary
```

### 5. Test Transaction Flow

```bash
# Without token (should fail)
cast send $SAFE "execTransaction(...)" --rpc-url base_sepolia

# With Notary token (should succeed)
# 1. Get approval token from Notary API
# 2. Encode with SDK: encodeTransaction(calldata, token)
# 3. Submit to Safe
```

## Testing

```bash
cd contracts
forge test                          # Run all tests
forge test --match-contract TollgateGuardRemovalTest  # Specific test
```

## Deployment History

| Network | Safe | Guard | Notary | Status |
|---------|------|-------|--------|--------|
| Base Sepolia | `0xB7D6...7E11` | `0xB519...C140` | `0x98A4...F36c` | ✅ Active |

## Project Structure

```
tollgate/
├── contracts/          # Solidity: Guard contract
│   ├── src/TollgateGuard.sol
│   ├── script/Deploy.s.sol Buddies  └── test/
├── core/               # Go: Notary server
│   ├── cmd/server/
│   ├── internal/
│   └── policies/policy.yaml
└── sdk/                # TypeScript: Client library
    └── src/encoder.ts
```

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment Guide](docs/deployment.md)
- [API Reference](docs/api.md)
- [Testing Guide](docs/testing.md)

## License

MIT