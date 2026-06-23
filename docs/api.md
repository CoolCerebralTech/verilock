# API Reference

## Notary Endpoints

### POST /v1/action-check

Requests an approval token for a transaction.

**Headers:**
- `Authorization: Bearer <agent_token>`
- `Content-Type: application/json`

**Body:**
```json
{
  "agent_id": "trading-bot-01",
  "action": "transfer",
  "destination": "0x090ff5f77950C069A5C39A60aB2a8cAeBC2ED563",
  "amount_usd": 20,
  "amount_raw": "20000000000000000",
  "purpose": "defi_yield_optimization",
  "chain_id": 84532,
  "nonce": "test-nonce-001",
  "timestamp": "2026-06-23T12:00:00Z"
}
```

**Response:**
```json
{
  "status": "approved",
  "decision_id": "550e8400-e29b-41d4-a716-446655440000",
  "tier": 1,
  "approval_token": {
    "token_id": "...",
    "agent_id": "trading-bot-01",
    "destination": "0x090ff5f77950C069A5C39A60aB2a8cAeBC2ED563",
    "amount_raw": "20000000000000000",
    "chain_id": 84532,
    "nonce": "...",
    "expires_at": 1719168000,
    "signature": "0x..."
  }
}
```

**Status codes:**
- `200` + `status: "approved"` — Token ready
- `200` + `status: "pending_human"` — Tier 3, poll `/v1/decision/:id`
- `400` — Bad request (missing fields)
- `401` — Unauthorized (invalid agent token)
- `403` — Denied (policy violation)

### GET /v1/decision/:id

Polls for a Tier 3 decision status.

**Response:**
```json
{
  "status": "approved",
  "decision_id": "550e8400-e29b-41d4-a716-446655440000",
  "approval_token": { ... }
}
```

### GET /v1/health

Health check (no auth required).

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.1"
}
```

## Guard Contract Interface

### checkTransaction

Called by Safe before every transaction.

```solidity
function checkTransaction(
    address to,
    uint256 value,
    bytes calldata data,
    uint8 operation,
    uint256 safeTxGas,
    uint256 baseGas,
    uint256 gasPrice,
    address gasToken,
    address payable refundReceiver,
    bytes calldata signatures,
    address msgSender
) external;
```

**Reverts with:**
- `OnlySafe()` — caller is not the Safe
- `GuardIsPaused()` — Guard is paused
- `TokenMissing()` — no valid token found in data
- `TokenExpired()` — token past expiry
- `TokenNonceReplayed()` — nonce already used
- `SignatureInvalid()` — signature doesn't recover to Notary

### checkAfterExecution

Called by Safe after every transaction.

```solidity
function checkAfterExecution(bytes32 txHash, bool success) external;
```

**Marks the token nonce as consumed to prevent replay.**

### Events

```solidity
event TransactionApproved(
    bytes32 indexed tokenId,
    address indexed destination,
    uint256 amountRaw,
    string agentId,
    bytes32 policyHash
);

event GuardPaused(bool isPaused);
```