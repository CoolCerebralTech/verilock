/**
 * simple-agent — Tollgate in 20 lines
 *
 * The bare minimum to send a policy-protected transaction on Base.
 * This is the first thing a developer should run after setup.
 *
 * Setup:
 *   1. Start the Notary:  cd ../../core && go run ./cmd/server/main.go
 *   2. Copy the Bearer token from the Notary startup log (the v1.eyJ... part)
 *   3. Paste it into AGENT_TOKEN below
 *   4. Run: npx tsx index.ts
 *
 * Add this file to .gitignore before pasting any real token.
 */

import { TollgateSigner } from '../../sdk/src/index.js';

// ── Config — fill in AGENT_TOKEN, leave everything else ──────────────────────
// ownerPrivateKey is only used for sendTransaction() — not needed for simulate().
// The dummy value below is safe to leave as-is for simulate-only runs.

const AGENT_TOKEN = '';  // ← paste the v1.eyJ... token from Notary startup log

const CONFIG = {
  notaryUrl:       'http://localhost:8080',
  agentToken:      AGENT_TOKEN,
  agentId:         'trading-bot-01',
  safeAddress:     '0x76Db37E62F080Fe2EAa78DF9089b7daCb155A5A6' as `0x${string}`,
  ownerPrivateKey: '0x0000000000000000000000000000000000000000000000000000000000000001' as `0x${string}`,
};

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  if (!AGENT_TOKEN) {
    throw new Error('AGENT_TOKEN is empty — paste the v1.eyJ... token from Notary startup log');
  }

  const tollgate = await TollgateSigner.create(CONFIG);
  console.log('✓ Connected to Tollgate Notary');

  // simulate() calls the Notary and returns the decision — without hitting the chain.
  // Use sendTransaction() to submit a real on-chain transaction.
  const result = await tollgate.simulate({
    to:        '0xDEF4560000000000000000000000000000000000',
    value:     10_000_000n,
    amountUsd: 10.00,
    purpose:   'defi_yield_optimization',
  });

  if (result.status === 'approved') {
    console.log('✓ Transaction approved by Tollgate');
    console.log('  Token ID  :', result.approval_token.token_id);
    console.log('  Tier      :', result.approval_token.tier);
    console.log('  Expires   :', result.approval_token.expires_at);
    console.log('  Risk score:', result.approval_token.risk_score);
    console.log('  Signature :', result.approval_token.signature.slice(0, 22) + '...');
  } else if (result.status === 'approved_with_notification') {
    console.log('✓ Transaction approved (Tier 2 — notification sent)');
    console.log('  Veto window:', result.veto_window_seconds + 's');
    console.log('  Token ID   :', result.approval_token.token_id);
  } else if (result.status === 'pending_human') {
    console.log('⏳ Awaiting human approval (Tier 3)');
    console.log('  Decision ID:', result.decision_id);
    console.log('  Poll URL   :', result.poll_url);
  } else if (result.status === 'denied') {
    console.log('✗ Transaction denied');
    console.log('  Code   :', result.code);
    console.log('  Message:', result.message);
  }
}

main().catch((err: unknown) => {
  console.error('✗', err instanceof Error ? err.message : String(err));
});