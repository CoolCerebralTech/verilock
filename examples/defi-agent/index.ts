/**
 * defi-agent — A complete DeFi trading agent with Tollgate protection
 *
 * Demonstrates:
 *   - All three tiers (auto-approve, notify+veto, human approval)
 *   - Purpose binding enforcement
 *   - Destination allowlist enforcement
 *   - Per-transaction spend limit enforcement
 *   - Behavioral baseline risk scoring
 *   - Human approval callbacks
 *   - Full error handling for every denial type
 *
 * Setup:
 *   1. Start the Notary:  cd ../../core && go run ./cmd/server/main.go
 *   2. Copy the Bearer token from the Notary startup log
 *   3. Paste it into AGENT_TOKEN below
 *   4. Run: npx tsx index.ts
 *
 * Add this file to .gitignore before pasting any real token.
 */

import {
  TollgateSigner,
  TollgateTransactionDeniedError,
  TollgateTokenExpiredError,
} from '../../sdk/src/index.js';
import type { TxRequest } from '../../sdk/src/index.js';

// ── Config ────────────────────────────────────────────────────────────────────

const AGENT_TOKEN = '';  // ← paste the v1.eyJ... token from Notary startup log

const CONFIG = {
  notaryUrl:       'http://localhost:8080',
  agentToken:      AGENT_TOKEN,
  agentId:         'trading-bot-01',
  safeAddress:     '0x76Db37E62F080Fe2EAa78DF9089b7daCb155A5A6' as `0x${string}`,
  ownerPrivateKey: '0x0000000000000000000000000000000000000000000000000000000000000001' as `0x${string}`,
  defaultPurpose:  'defi_yield_optimization',

  // Tier 3: fired when a transaction requires human approval
  onPendingHumanApproval: (id: string) => {
    log(`  ⏳ Awaiting human approval... (decision: ${id})`);
    log(`     Poll: GET http://localhost:8080/v1/decision/${id}`);
  },
  onHumanApprovalReceived: (id: string) => {
    log(`  ✓ Human approved (decision: ${id})`);
  },

  // Tier 2: fired when transaction executes with a notification + veto window
  onApprovedWithNotification: (id: string, vetoWindowSeconds: number) => {
    log(`  📢 Notification sent — veto window: ${vetoWindowSeconds}s (decision: ${id})`);
  },
};

// Whitelisted destination from policy.yaml
const POOL_A = '0xDEF4560000000000000000000000000000000000' as const;

// ── Helpers ───────────────────────────────────────────────────────────────────

function log(msg: string) {
  console.log(`[${new Date().toISOString().slice(11, 23)}] ${msg}`);
}

async function tryTransaction(
  tollgate: TollgateSigner,
  label: string,
  params: TxRequest,
) {
  log(`→ ${label}`);
  try {
    const result = await tollgate.simulate(params);

    if (result.status === 'approved') {
      log(`  ✓ APPROVED (Tier ${result.approval_token.tier}) | risk: ${result.approval_token.risk_score.toFixed(2)} | auto: ${result.approval_token.auto_approved}`);
    } else if (result.status === 'approved_with_notification') {
      log(`  ✓ APPROVED WITH NOTIFICATION (Tier 2) | veto: ${result.veto_window_seconds}s | risk: ${result.approval_token.risk_score.toFixed(2)}`);
    } else if (result.status === 'pending_human') {
      log(`  ⏳ PENDING HUMAN APPROVAL (Tier 3)`);
      log(`     Poll: ${result.poll_url} every ${result.poll_interval_seconds}s`);
    } else if (result.status === 'denied') {
      log(`  ✗ DENIED [${result.code}]: ${result.message}`);
    }
  } catch (err) {
    if (err instanceof TollgateTransactionDeniedError) {
      log(`  ✗ DENIED [${err.denialCode}]: ${err.denialMessage}`);
    } else if (err instanceof TollgateTokenExpiredError) {
      log(`  ✗ TOKEN EXPIRED: ${err.message}`);
    } else {
      log(`  ✗ ERROR: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  console.log();
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  if (!AGENT_TOKEN) {
    throw new Error('AGENT_TOKEN is empty — paste the v1.eyJ... token from Notary startup log');
  }

  log('Starting DeFi agent with Tollgate protection...');
  const tollgate = await TollgateSigner.create(CONFIG);
  log('✓ Connected to Tollgate Notary\n');

  // ── Test 1: Tier 1 — auto-approve ($10, below $50 threshold) ─────────────
  await tryTransaction(tollgate, 'Small swap $10 — expect Tier 1 auto-approve', {
    to: POOL_A, value: 10_000_000n, amountUsd: 10,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 2: Tier 2 — notify + veto ($75, between $50 and $200) ───────────
  await tryTransaction(tollgate, 'Medium swap $75 — expect Tier 2 notify+veto', {
    to: POOL_A, value: 75_000_000n, amountUsd: 75,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 3: Tier 3 — human approval ($300, above $200 threshold) ──────────
  await tryTransaction(tollgate, 'Large swap $300 — expect Tier 3 human approval', {
    to: POOL_A, value: 300_000_000n, amountUsd: 300,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 4: Denied — purpose mismatch ────────────────────────────────────
  await tryTransaction(tollgate, 'NFT purchase — expect PURPOSE_MISMATCH denial', {
    to: POOL_A, value: 10_000_000n, amountUsd: 10,
    purpose: 'buy_nfts',
  });

  // ── Test 5: Denied — unknown destination ─────────────────────────────────
  await tryTransaction(tollgate, 'Unknown pool — expect DESTINATION_NOT_ALLOWED denial', {
    to: '0x9999990000000000000000000000000000000000' as `0x${string}`,
    value: 10_000_000n, amountUsd: 10,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 6: Denied — exceeds per-transaction limit ────────────────────────
  await tryTransaction(tollgate, 'Whale swap $600 — expect EXCEEDS_TRANSACTION_LIMIT denial', {
    to: POOL_A, value: 600_000_000n, amountUsd: 600,
    purpose: 'defi_yield_optimization',
  });

  log('Session complete.');
  log('Check the audit log:');
  log('  sqlite3 ../../core/data/audit.db \\');
  log('    "SELECT decision, tier, denial_code, amount_usd FROM decisions ORDER BY created_at DESC LIMIT 10;"');
}

main().catch((err: unknown) => {
  console.error('✗', err instanceof Error ? err.message : String(err));
});