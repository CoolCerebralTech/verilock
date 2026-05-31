# Policy Reference

The Tollgate policy file is a human-readable YAML document that defines exactly what each AI agent is and is not allowed to do. It is the legal contract between the agent and the humans who deployed it.

**Key properties:**
- Written in plain YAML — CFOs and compliance officers can read and sign off on it
- Hot-reloaded — changes take effect on the next request without restarting the server
- Version-controlled — every change is timestamped and requires the identity of who made it
- Multi-signature change control — no single person can modify a live policy alone
- Immutable audit trail — every decision records the exact policy version that governed it

---

## Complete Policy Schema

```yaml
# Policy file version — stored with every audit record
version: "1.0.0"
updated_at: "2026-05-28T00:00:00Z"
updated_by: "founder@yourcompany.com"

agents:
  - id: "trading-bot-01"              # Unique agent identifier — must match agentId in SDK
    name: "DeFi Trading Agent"         # Human-readable label for dashboards
    enabled: true                      # Set false to instantly disable a compromised agent

    purpose: "defi_yield_optimization" # Primary purpose label
    clearance_level: 2                 # 1=lowest, 5=highest — for future tiered policies

    spend_limits:
      max_per_transaction_usd: 500     # Hard limit per transaction
      max_per_hour_usd: 2000           # Rolling 1-hour window
      max_per_day_usd: 5000            # Rolling 24-hour window
      auto_approve_below_usd: 50       # No human review needed below this
      require_human_above_usd: 100     # Always route to human above this

    allowed_destinations:              # Explicit allowlist — all others denied
      - "0xABC123..."                  # Whitelisted contract addresses
      - "0xDEF456..."

    blocked_destinations:              # Explicit blocklist — checked first
      - "0x000000..."                  # Zero address — always blocked

    allowed_purposes:                  # Exact string match — case sensitive
      - "defi_yield_optimization"
      - "liquidity_provision"

    reject_unsolicited_permissions: true  # Blocks NFT-style permission expansion

    behavioral_risk_threshold: 0.7     # Block requests scoring above this (0.0-1.0)
    behavioral_review_threshold: 0.4   # Flag for attention above this — do not block

global_rules:
  default_action: "deny"              # MUST be "deny" — unknown agents always denied
  max_request_age_seconds: 30         # Reject requests older than 30 seconds
  require_nonce: true                 # Every request must include a unique nonce
  nonce_window_seconds: 120           # Nonces valid for 2 minutes
```

---

## Field Reference

### Agent Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | ✅ | Unique identifier. Must match `agentId` in the SDK config. |
| `name` | string | ✅ | Human-readable name for logs and dashboards. |
| `enabled` | boolean | ✅ | `false` instantly disables the agent. All requests denied. |
| `clearance_level` | integer 1-5 | ✅ | Reserved for tiered policy enforcement. |

### Spend Limits

| Field | Type | Description |
|-------|------|-------------|
| `max_per_transaction_usd` | number | Hard cap per single transaction. Requests above this are denied immediately. |
| `max_per_hour_usd` | number | Rolling 1-hour total. Checked against audit log. |
| `max_per_day_usd` | number | Rolling 24-hour total. Checked against audit log. |
| `auto_approve_below_usd` | number | Requests below this amount are approved without human review. |
| `require_human_above_usd` | number | Requests above this amount are routed to a human approver. |

### Destination Control

| Field | Type | Description |
|-------|------|-------------|
| `allowed_destinations` | string[] | Whitelist of contract addresses. All others denied. Case-insensitive. |
| `blocked_destinations` | string[] | Explicit blocklist. Checked before the allowlist. Takes priority. |

### Purpose Binding

| Field | Type | Description |
|-------|------|-------------|
| `allowed_purposes` | string[] | Exact match, case-sensitive. Request purpose must be in this list. |
| `reject_unsolicited_permissions` | boolean | Blocks attempts to expand permissions beyond the original purpose. |

### Behavioral Thresholds

| Field | Type | Description |
|-------|------|-------------|
| `behavioral_risk_threshold` | float 0.0-1.0 | Requests scoring above this are denied even if all rules pass. |
| `behavioral_review_threshold` | float 0.0-1.0 | Requests scoring above this are flagged in the audit log but not denied. |

---

## Evaluation Order

The policy engine evaluates checks in strict order. The first failing check stops evaluation:

1. **Request age** — reject replayed or stale requests
2. **Nonce uniqueness** — prevent replay attacks
3. **Agent existence** — unknown agents always denied
4. **Agent enabled** — disabled agents always denied
5. **Purpose binding** — purpose must be in `allowed_purposes`
6. **Blocked destination** — checked before allowlist
7. **Allowed destination** — must be in `allowed_destinations`
8. **Per-transaction limit** — amount must not exceed `max_per_transaction_usd`
9. **Hourly and daily limits** — rolling window spend checks
10. **Behavioral baseline** — anomaly score must not exceed threshold
11. **Route decision** — auto-approve, pending human, or approved

---

## Denial Codes

When a request is denied, the response includes a machine-readable code:

| Code | Cause |
|------|-------|
| `REQUEST_EXPIRED` | Request timestamp is older than `max_request_age_seconds` |
| `NONCE_REPLAY` | Nonce has already been used |
| `AGENT_UNKNOWN` | Agent ID not found in policy |
| `AGENT_DISABLED` | Agent exists but `enabled: false` |
| `PURPOSE_MISMATCH` | Request purpose not in `allowed_purposes` |
| `DESTINATION_BLOCKED` | Destination is in `blocked_destinations` |
| `DESTINATION_NOT_ALLOWED` | Destination not in `allowed_destinations` |
| `EXCEEDS_TRANSACTION_LIMIT` | Amount exceeds `max_per_transaction_usd` |
| `EXCEEDS_HOURLY_LIMIT` | Would exceed `max_per_hour_usd` rolling window |
| `EXCEEDS_DAILY_LIMIT` | Would exceed `max_per_day_usd` rolling window |
| `BEHAVIORAL_ANOMALY` | Risk score exceeds `behavioral_risk_threshold` |
| `ZERO_AMOUNT` | Zero-value transactions are never permitted |
| `POLICY_UNAVAILABLE` | Policy file cannot be read — all requests denied |

---

## Behavioral Baseline Engine

The behavioral engine tracks each agent's transaction patterns over time and flags significant deviations — even when the transaction technically passes all YAML rules.

**What it tracks:**
- Transaction frequency (requests per hour)
- Amount distribution (mean and standard deviation)
- Destination diversity (new addresses raise the score)
- Timing patterns (unusual hours raise the score)

**Risk score formula:**
```
risk_score = (frequency_score × 0.35)
           + (amount_score    × 0.40)
           + (destination_score × 0.15)
           + (timing_score    × 0.10)
```

A new agent with fewer than 20 approved transactions always scores 0.0 — the engine does not produce false positives before a baseline is established.

---

## Hot Reload

The policy file is watched for changes using `fsnotify`. When you save an updated policy:

1. The Notary detects the file change within milliseconds
2. It parses and validates the new policy
3. If valid: the new policy is atomically activated — the next request uses it
4. If invalid: the previous valid policy remains active — no requests are denied due to a bad edit

The server does not restart. In-flight requests complete against the policy that was active when they arrived.

---

## Security Notes

- Changing a policy requires multi-signature authorization — no single person can modify a live policy
- Every policy version is stored with a keccak256 hash embedded in every Approval Token
- A regulator asking "what rules governed transaction X" receives the exact policy file active at that timestamp, cryptographically proven unaltered
- Setting `enabled: false` on an agent takes effect on the next request — under 1ms