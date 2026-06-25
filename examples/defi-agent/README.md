# defi-agent

A complete DeFi trading agent demonstrating every Verilock feature across all three tiers.

## What it demonstrates

| Test | Expected result |
|------|----------------|
| $10 swap | Tier 1 auto-approve (or Tier 3 if agent is cold) |
| $75 swap | Tier 2 — approved + notification sent + veto window |
| $300 swap | Tier 3 — blocks until human approves |
| Wrong purpose | `PURPOSE_MISMATCH` denial |
| Unknown destination | `DESTINATION_NOT_ALLOWED` denial |
| $600 swap | `EXCEEDS_TRANSACTION_LIMIT` denial |

## Run it

```bash
# Terminal 1 — start the Notary
cd ../../core
go run ./cmd/server/main.go

# Terminal 2 — paste your token and run
cd examples/defi-agent
# Open index.ts and paste your token into AGENT_TOKEN
npx tsx index.ts
```

## Expected output

```
[13:10:01.000] Starting DeFi agent with Verilock protection...
[13:10:01.052] ✓ Connected to Verilock Notary

[13:10:01.053] → Small swap $10 — expect Tier 1 auto-approve
[13:10:01.120]   ✓ APPROVED (Tier 1) | risk: 0.00 | auto: true

[13:10:01.121] → Medium swap $75 — expect Tier 2 notify+veto
[13:10:01.189]   ✓ APPROVED WITH NOTIFICATION (Tier 2) | veto: 120s | risk: 0.00

[13:10:01.190] → Large swap $300 — expect Tier 3 human approval
[13:10:01.245]   ⏳ PENDING HUMAN APPROVAL (Tier 3)
[13:10:01.245]      Poll: /v1/decision/... every 3s

[13:10:01.246] → NFT purchase — expect PURPOSE_MISMATCH denial
[13:10:01.301]   ✗ DENIED [PURPOSE_MISMATCH]: Requested purpose is not permitted for this agent.

[13:10:01.302] → Unknown pool — expect DESTINATION_NOT_ALLOWED denial
[13:10:01.356]   ✗ DENIED [DESTINATION_NOT_ALLOWED]: Destination address is not on the allow list.

[13:10:01.357] → Whale swap $600 — expect EXCEEDS_TRANSACTION_LIMIT denial
[13:10:01.410]   ✗ DENIED [EXCEEDS_TRANSACTION_LIMIT]: Transaction amount exceeds the per-transaction limit.
```

> **Note on cold-start:** On a fresh server, Tier 1 ($10) and Tier 2 ($75)
> will both route to Tier 3 (pending human) until the agent accumulates
> 20 approved transactions. This is the cold-start protection working correctly.
> Set `min_data_points_for_auto_approve: 0` in `policy.yaml` to disable it
> during development.

## Check the audit log

Every decision — approved and denied — is recorded:

```bash
sqlite3 ../../core/data/audit.db \
  "SELECT decision, tier, denial_code, amount_usd
   FROM decisions ORDER BY created_at DESC LIMIT 10;"
```

## Tier routing thresholds

These come from `policy.yaml` for `trading-bot-01`:

| Amount | Tier | Behaviour |
|--------|------|-----------|
| ≤ $50 | 1 | Auto-approve (no human involved) |
| $50–$200 | 2 | Approve + notify + 120s veto window |
| > $200 | 3 | Block until human approves |
| > $500 | — | Denied (exceeds max_per_transaction_usd) |

Edit `../../core/policies/policy.yaml` to change these thresholds.
Changes take effect immediately — no Notary restart needed.