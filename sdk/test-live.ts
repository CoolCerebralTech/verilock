/**
 * @file test-live.ts
 * Live integration test against a running Verilock Notary.
 *
 * SECURITY: Only agentToken is needed for simulate() tests.
 *           ownerPrivateKey is only needed for actual on-chain submission.
 *
 * Add to .gitignore:  sdk/test-live.ts
 *
 * Usage:
 *   npx tsx test-live.ts
 *
 * Prerequisites:
 *   - Notary running: go run ./cmd/server  (in core/)
 *   - Paste your agentToken below (from the Notary startup log)
 */

import { VerilockSigner } from './src/index.js';
import type { NotaryResponse } from './src/types.js';

// ── CONFIG ────────────────────────────────────────────────────────────────────
// Fill in agentToken — that is the only thing needed for simulate() tests.
//
// ownerPrivateKey is only required if you set RUN_ONCHAIN = true below.
// It must be the private key of a Safe OWNER (the address listed as an owner
// on your Gnosis Safe). For a 1-of-1 Safe on testnet that is your deployer key.
// It is NOT your personal wallet key unless your wallet IS a Safe owner.

const AGENT_TOKEN = 'v1.eyJhZ2VudF9pZCI6InRyYWRpbmctYm90LTAxIiwiaXNzdWVkX2F0IjoiMjAyNi0wNi0xMVQwMzo1NzoyNFoiLCJleHBpcmVzX2F0IjoiMjAyNi0wNy0xMVQwMzo1NzoyNFoiLCJ0b2tlbl9pZCI6ImE0MTBiZjBmLTlkZmUtNDNiMS1iZjNlLTgyZTU4ZDE3MWUwZCJ9.kxw4_Gz9g2QIgOw5qTYJJH2bzw3Mzo_QKHrDi53vA9Y';  // ← paste the v1.eyJ... token from Notary startup log

const SAFE_ADDRESS  = '0x76Db37E62F080Fe2EAa78DF9089b7daCb155A5A6' as `0x${string}`;
const DESTINATION   = '0xDEF4560000000000000000000000000000000000' as `0x${string}`;
const NOTARY_URL    = 'http://localhost:8080';
const AGENT_ID      = 'trading-bot-01';

// Set to true only when you want to submit a real on-chain transaction.
// Requires OWNER_PRIVATE_KEY to be set below.
const RUN_ONCHAIN   = false;
const OWNER_PRIVATE_KEY = '' as `0x${string}`;  // only needed when RUN_ONCHAIN = true

// ── Validation ────────────────────────────────────────────────────────────────

function check(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`CONFIG: ${message}`);
}

// ── Result printer ────────────────────────────────────────────────────────────

function printResult(result: NotaryResponse) {
  if (result.status === 'approved') {
    console.log(`   status  : approved (Tier ${result.approval_token.tier})`);
    console.log(`   token   : ${result.approval_token.token_id}`);
    console.log(`   expires : ${result.approval_token.expires_at}`);
    console.log(`   sig     : ${result.approval_token.signature.slice(0, 22)}...`);
    console.log(`   risk    : ${result.approval_token.risk_score}`);
  } else if (result.status === 'approved_with_notification') {
    console.log(`   status  : approved_with_notification (Tier 2)`);
    console.log(`   veto    : ${result.veto_window_seconds}s window`);
    console.log(`   token   : ${result.approval_token.token_id}`);
    console.log(`   sig     : ${result.approval_token.signature.slice(0, 22)}...`);
  } else if (result.status === 'pending_human') {
    console.log(`   status  : pending_human (Tier 3)`);
    console.log(`   poll    : ${result.poll_url}`);
    console.log(`   every   : ${result.poll_interval_seconds}s`);
  } else if (result.status === 'denied') {
    console.log(`   status  : denied`);
    console.log(`   code    : ${result.code}`);
    console.log(`   message : ${result.message}`);
  }
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  check(AGENT_TOKEN.length > 0, 'AGENT_TOKEN is empty — paste the v1.eyJ... token from Notary startup log');
  if (RUN_ONCHAIN) {
    check(OWNER_PRIVATE_KEY.length > 0,        'OWNER_PRIVATE_KEY is required for on-chain test');
    check(OWNER_PRIVATE_KEY.startsWith('0x'), 'OWNER_PRIVATE_KEY must start with 0x');
  }

  console.log('');
  console.log('─────────────────────────────────────────');
  console.log('  Verilock SDK — Live Integration Test');
  console.log('─────────────────────────────────────────');
  console.log(`  Notary  : ${NOTARY_URL}`);
  console.log(`  Safe    : ${SAFE_ADDRESS}`);
  console.log(`  On-chain: ${RUN_ONCHAIN}`);
  console.log('─────────────────────────────────────────');
  console.log('');

  // ── Connect ───────────────────────────────────────────────────────────────
  console.log('1. Connecting to Notary...');
  const verilock = await VerilockSigner.create({
    notaryUrl:       NOTARY_URL,
    agentToken:      AGENT_TOKEN,
    agentId:         AGENT_ID,
    safeAddress:     SAFE_ADDRESS,
    ownerPrivateKey: RUN_ONCHAIN ? OWNER_PRIVATE_KEY : '0x0000000000000000000000000000000000000000000000000000000000000001' as `0x${string}`,
  });
  console.log(`   ✓ connected — chain ${verilock.getChainId()}`);

  // ── Tier 1: $10, below auto_approve_below_usd ($50) ──────────────────────
  console.log('\n2. Simulate $10 — Tier 1 (auto-approve)...');
  const r1 = await verilock.simulate({ to: DESTINATION, value: 10_000_000n, amountUsd: 10, purpose: 'defi_yield_optimization' });
  printResult(r1);

  // ── Tier 2: $100, between $50 and $200 ───────────────────────────────────
  console.log('\n3. Simulate $100 — Tier 2 (notify + veto)...');
  const r2 = await verilock.simulate({ to: DESTINATION, value: 100_000_000n, amountUsd: 100, purpose: 'defi_yield_optimization' });
  printResult(r2);

  // ── Tier 3: $300, above require_human_above_usd ($200) ───────────────────
  console.log('\n4. Simulate $300 — Tier 3 (human approval)...');
  const r3 = await verilock.simulate({ to: DESTINATION, value: 300_000_000n, amountUsd: 300, purpose: 'defi_yield_optimization' });
  printResult(r3);

  // ── Denied: wrong purpose ─────────────────────────────────────────────────
  console.log('\n5. Simulate wrong purpose — denied...');
  const r4 = await verilock.simulate({ to: DESTINATION, value: 10_000_000n, amountUsd: 10, purpose: 'not_in_policy' });
  printResult(r4);

  // ── Denied: above max_per_transaction ($500) ──────────────────────────────
  console.log('\n6. Simulate $600 — denied (exceeds tx limit)...');
  const r5 = await verilock.simulate({ to: DESTINATION, value: 600_000_000n, amountUsd: 600, purpose: 'defi_yield_optimization' });
  printResult(r5);

  // ── Assertions ────────────────────────────────────────────────────────────
  console.log('\n─────────────────────────────────────────');
  const results: Array<[string, boolean]> = [
    ['$10 approved or pending',   r1.status === 'approved' || r1.status === 'approved_with_notification' || r1.status === 'pending_human'],
    ['$100 not denied',           r2.status !== 'denied'],
    ['$300 tier3 or higher',      r3.status === 'pending_human' || r3.status === 'approved_with_notification'],
    ['wrong purpose → denied',    r4.status === 'denied'],
    ['wrong purpose → PURPOSE_MISMATCH', r4.status === 'denied' && r4.code === 'PURPOSE_MISMATCH'],
    ['$600 → denied',             r5.status === 'denied'],
    ['$600 → EXCEEDS_TRANSACTION_LIMIT', r5.status === 'denied' && r5.code === 'EXCEEDS_TRANSACTION_LIMIT'],
  ];

  let passed = 0;
  for (const [name, ok] of results) {
    console.log(`  ${ok ? '✓' : '✗'} ${name}`);
    if (ok) passed++;
  }

  console.log('─────────────────────────────────────────');
  console.log(`  ${passed}/${results.length} assertions passed`);

  if (passed < results.length) {
    throw new Error(`${results.length - passed} assertion(s) failed`);
  }

  // ── Optional on-chain test ────────────────────────────────────────────────
  if (RUN_ONCHAIN) {
    console.log('\n7. Submitting $10 on-chain via Safe...');
    console.log('   (Safe must hold ETH and Guard must be attached)');
    const txHash = await verilock.sendTransaction({
      to: DESTINATION, value: 10_000_000n, amountUsd: 10, purpose: 'defi_yield_optimization',
    });
    console.log(`   ✓ txHash: ${txHash}`);
  }

  console.log('');
  console.log('  Done. No on-chain transactions were submitted.');
  console.log('  Set RUN_ONCHAIN = true to test the full flow.');
  console.log('─────────────────────────────────────────');
  console.log('');
}

main().catch((err: unknown) => {
  console.error('\n✗', err instanceof Error ? err.message : String(err));
  throw err;
});