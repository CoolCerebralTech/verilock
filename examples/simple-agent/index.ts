/**
 * simple-agent — Tollgate in 20 lines
 *
 * The bare minimum to send a policy-protected transaction on Base.
 * This is the first thing a developer should run after setup.
 *
 * Setup:
 *   1. Start the Notary:  cd ../../core && go run ./cmd/server/main.go
 *   2. Copy the Bearer token from the Notary startup log
 *   3. Fill in the config below
 *   4. Run: npx tsx index.ts
 */

import { TollgateSigner } from '../../sdk/src/index.js';

async function main() {
  // Create the signer — validates config and checks Notary is reachable
  const tollgate = await TollgateSigner.create({
    notaryUrl:       'http://localhost:8080',
    agentToken:      process.env['AGENT_TOKEN']  ?? '',
    agentId:         'trading-bot-01',
    safeAddress:     (process.env['SAFE_ADDRESS']  ?? '0x0000000000000000000000000000000000000001') as `0x${string}`,
    ownerPrivateKey: (process.env['OWNER_KEY'] ?? '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80') as `0x${string}`,
  });

  console.log('✓ Connected to Tollgate Notary');

  // simulate() calls the Notary and returns the decision — without hitting the chain.
  // Use sendTransaction() instead to submit a real transaction.
  const result = await tollgate.simulate({
    to:        '0xdef4560000000000000000000000000000000000',
    value:     BigInt(10_000_000),   // wei
    amountUsd: 10.00,
    purpose:   'defi_yield_optimization',
  });

  if (result.status === 'approved') {
    console.log('✓ Transaction approved by Tollgate');
    console.log('  Token ID  :', result.approval_token.token_id);
    console.log('  Expires   :', result.approval_token.expires_at);
    console.log('  Risk score:', result.approval_token.risk_score);
    console.log('  Signature :', result.approval_token.signature.slice(0, 20) + '...');
  } else if (result.status === 'denied') {
    console.log('✗ Transaction denied');
    console.log('  Code    :', result.code);
    console.log('  Reason  :', result.message);
  }
}

main().catch(console.error);