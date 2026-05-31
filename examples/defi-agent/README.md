# defi-agent

A complete DeFi trading agent example demonstrating every Tollgate feature.

## What it demonstrates

- ✅ Auto-approved small transactions (below threshold)
- ✅ Larger transactions flagged for review
- ✅ Purpose mismatch denial (`buy_nfts` rejected)
- ✅ Unknown destination denial
- ✅ Spend limit enforcement ($600 > $500 limit)
- ✅ Behavioral baseline — new destinations get higher risk scores
- ✅ Human approval callbacks
- ✅ Full error handling for every denial type

## Run it

```bash
# Terminal 1 — start the Notary
cd ../../core
go run ./cmd/server/main.go

# Terminal 2 — run the agent
cd examples/defi-agent
AGENT_TOKEN=your_token npx tsx index.ts
```

## Expected output

```
[2026-05-28T...] Starting DeFi agent with Tollgate protection...
[2026-05-28T...] ✓ Connected to Tollgate Notary

[2026-05-28T...] → Small swap — should auto-approve ($10)
[2026-05-28T...]   ✓ APPROVED | risk: 0.00 | auto: true

[2026-05-28T...] → Medium swap — above auto-approve ($75)
[2026-05-28T...]   ✓ APPROVED | risk: 0.00 | auto: false

[2026-05-28T...] → NFT purchase — purpose mismatch (should deny)
[2026-05-28T...]   ✗ DENIED [PURPOSE_MISMATCH]: Purpose "buy_nfts" is not in the agent's allowed_purposes list.

[2026-05-28T...] → Unknown destination — not whitelisted (should deny)
[2026-05-28T...]   ✗ DENIED [DESTINATION_NOT_ALLOWED]: Destination is not in allowed_destinations.

[2026-05-28T...] → Large swap — exceeds $500 limit (should deny)
[2026-05-28T...]   ✗ DENIED [EXCEEDS_TRANSACTION_LIMIT]: Amount $600.00 exceeds limit of $500.00.

[2026-05-28T...] → Pool B — new destination (watch risk score)
[2026-05-28T...]   ✓ APPROVED | risk: 0.00 | auto: true
```

## Check the audit log

After running, inspect every decision:

```bash
sqlite3 ../../core/data/audit.db \
  "SELECT agent_id, decision, denial_code, amount_usd, created_at
   FROM decisions ORDER BY created_at DESC LIMIT 10;"
```