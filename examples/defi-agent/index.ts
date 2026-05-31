/**
 * defi-agent — A complete DeFi trading agent with Tollgate protection
 *
 * Demonstrates:
 *   - Multiple transaction types with purpose binding
 *   - Spend limit enforcement across a session
 *   - Behavioral baseline — the 4th transaction to a new destination
 *     will have a higher risk score
 *   - Error handling for every denial type
 *   - Human approval callback for high-value transactions
 *
 * Run:
 *   cd ../../core && go run ./cmd/server/main.go  (terminal 1)
 *   cd examples/defi-agent && AGENT_TOKEN=xxx npx tsx index.ts  (terminal 2)
 */

import {
  TollgateSigner,
  TollgateTransactionDeniedError,
  TollgateTokenExpiredError,
} from '../../sdk/src/index.js';

// ── CONFIG ────────────────────────────────────────────────────────────────────

const NOTARY_URL  = 'http://localhost:8080';
const AGENT_TOKEN = process.env['AGENT_TOKEN'] ?? '';
const AGENT_ID    = 'trading-bot-01';
const SAFE        = (process.env['SAFE_ADDRESS'] ?? '0x0000000000000000000000000000000000000001') as `0x${string}`;
const OWNER_KEY   = (process.env['OWNER_KEY'] ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80') as `0x${string}`;

// Known whitelisted destinations from policy.yaml
const POOL_A = '0xdef4560000000000000000000000000000000000' as const;
const POOL_B = '0xabc1230000000000000000000000000000000000' as const;

// ── HELPERS ───────────────────────────────────────────────────────────────────

function log(msg: string) {
  console.log(`[${new Date().toISOString()}] ${msg}`);
}

async function tryTransaction(
  tollgate: TollgateSigner,
  label: string,
  params: Parameters<TollgateSigner['simulate']>[0],
) {
  log(`→ ${label}`);
  try {
    const result = await tollgate.simulate(params);
    if (result.status === 'approved') {
      log(`  ✓ APPROVED | risk: ${result.approval_token.risk_score.toFixed(2)} | auto: ${result.approval_token.auto_approved}`);
    } else if (result.status === 'denied') {
      log(`  ✗ DENIED [${result.code}]: ${result.message}`);
    } else {
      log(`  ⏳ PENDING HUMAN APPROVAL`);
    }
  } catch (err) {
    if (err instanceof TollgateTransactionDeniedError) {
      log(`  ✗ DENIED [${err.denialCode}]: ${err.denialMessage}`);
    } else if (err instanceof TollgateTokenExpiredError) {
      log(`  ✗ TOKEN EXPIRED: ${err.message}`);
    } else {
      log(`  ✗ ERROR: ${String(err)}`);
    }
  }
  console.log();
}

// ── MAIN ──────────────────────────────────────────────────────────────────────

async function main() {
  log('Starting DeFi agent with Tollgate protection...');

  const tollgate = await TollgateSigner.create({
    notaryUrl:  NOTARY_URL,
    agentToken: AGENT_TOKEN,
    agentId:    AGENT_ID,
    safeAddress:     SAFE,
    ownerPrivateKey: OWNER_KEY,
    defaultPurpose:  'defi_yield_optimization',
    onPendingHumanApproval: (id) => {
      log(`  ⏳ Waiting for human approval... (decision: ${id})`);
    },
    onHumanApprovalReceived: (id) => {
      log(`  ✓ Human approved! (decision: ${id})`);
    },
  });

  log('✓ Connected to Tollgate Notary\n');

  // ── Test 1: Small transaction — auto-approved (below $50 threshold)
  await tryTransaction(tollgate, 'Small swap — should auto-approve ($10)', {
    to: POOL_A, value: BigInt(10_000_000), amountUsd: 10,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 2: Medium transaction — approved but recommended for review ($75)
  await tryTransaction(tollgate, 'Medium swap — above auto-approve ($75)', {
    to: POOL_A, value: BigInt(75_000_000), amountUsd: 75,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 3: Purpose mismatch — always denied
  await tryTransaction(tollgate, 'NFT purchase — purpose mismatch (should deny)', {
    to: POOL_A, value: BigInt(10_000_000), amountUsd: 10,
    purpose: 'buy_nfts',
  });

  // ── Test 4: Unknown destination — not in allowlist
  await tryTransaction(tollgate, 'Unknown destination — not whitelisted (should deny)', {
    to: '0x9999990000000000000000000000000000000000' as `0x${string}`,
    value: BigInt(10_000_000), amountUsd: 10,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 5: Exceeds transaction limit ($600 > $500 limit)
  await tryTransaction(tollgate, 'Large swap — exceeds $500 limit (should deny)', {
    to: POOL_A, value: BigInt(600_000_000), amountUsd: 600,
    purpose: 'defi_yield_optimization',
  });

  // ── Test 6: Second whitelisted pool — new destination (higher risk score)
  await tryTransaction(tollgate, 'Pool B — new destination (watch risk score)', {
    to: POOL_B, value: BigInt(20_000_000), amountUsd: 20,
    purpose: 'defi_yield_optimization',
  });

  log('Session complete. Check the audit log:');
  log('  sqlite3 ../../core/data/audit.db "SELECT agent_id, decision, denial_code, amount_usd FROM decisions ORDER BY created_at DESC LIMIT 10;"');
}

main().catch(console.error);