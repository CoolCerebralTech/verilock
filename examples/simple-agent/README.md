# simple-agent

The minimum viable Verilock integration — 30 lines of TypeScript.

## What it does

1. Creates a `VerilockSigner` connected to your local Notary
2. Calls `simulate()` with a $10 transaction
3. Prints the Notary's decision — approved, pending, or denied

No on-chain transaction is submitted. `simulate()` is read-only.

## Run it

```bash
# Terminal 1 — start the Notary
cd ../../core
go run ./cmd/server/main.go

# Terminal 2 — paste the token from the Notary startup log, then run
cd examples/simple-agent
# Open index.ts and paste your token into AGENT_TOKEN
npx tsx index.ts
```

## Expected output

```
✓ Connected to Verilock Notary
✓ Transaction approved by Verilock
  Token ID  : 9692d4ac-...
  Tier      : 3
  Expires   : 2026-06-11T...
  Risk score: 0
  Signature : 0x02b91613e3...
```

> **Note:** Tier 3 (pending human) on first run is expected — the agent
> has no behavioral history yet so cold-start protection routes everything
> to human approval. After 20 approved transactions it will auto-approve
> at Tier 1.

## Try a denial

Change `purpose` to something not in the policy:

```typescript
purpose: 'buy_nfts',
```

Output:
```
✗ Transaction denied
  Code   : PURPOSE_MISMATCH
  Message: Requested purpose is not permitted for this agent.
```

## Next step

Once this works, look at the `defi-agent` example for a complete demo
of all three tiers, spend limits, and behavioral baseline scoring.