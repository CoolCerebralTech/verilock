/**
 * @file types.ts
 * All type definitions, Zod schemas, ABI constants, and network constants.
 * Everything else in the SDK imports from here.
 */

import { z } from 'zod';

// ── APPROVAL TOKEN ──────────────────────────────────────────────────────────
// Mirrors the Notary approval_token JSON response exactly.
// snake_case field names match the Go JSON serialization.

export const ApprovalTokenSchema = z.object({
  token_id:       z.string().uuid(),
  agent_id:       z.string().min(1),
  policy_version: z.string(),
  policy_hash:    z.string().startsWith('0x'),

  // Approval path — which tier handled this decision.
  // 1 = auto-approved, 2 = approved with notification, 3 = human approved.
  tier:           z.number().int().min(1).max(3),
  auto_approved:  z.boolean(),

  action:         z.string(),
  destination:    z.string().startsWith('0x'),

  // .finite() rejects NaN and Infinity that z.number().positive() allows.
  amount_usd:     z.number().positive().finite(),
  amount_raw:     z.string().min(1),      // bigint as string — no float precision loss
  purpose:        z.string(),
  chain_id:       z.number().int().positive(),
  nonce:          z.string().min(1),
  issued_at:      z.string().datetime(),
  expires_at:     z.string().datetime(),
  risk_score:     z.number().min(0).max(1),
  signature:      z.string().startsWith('0x'), // 65-byte ECDSA sig, hex-encoded
});

export type ApprovalToken = z.infer<typeof ApprovalTokenSchema>;

// ── NOTARY RESPONSE ─────────────────────────────────────────────────────────
// Discriminated union on the status field.
//
// Three-tier routing produces four possible status values:
//   "approved"                  Tier 1 — token ready, submit immediately
//   "approved_with_notification"Tier 2 — token ready, notification sent,
//                                        veto window open (veto_window_seconds)
//   "pending_human"             Tier 3 — poll poll_url every poll_interval_seconds
//   "denied"                    all tiers — rejected, see code

export const NotaryResponseSchema = z.discriminatedUnion('status', [
  // Tier 1 — fully automatic
  z.object({
    status:         z.literal('approved'),
    decision_id:    z.string().uuid(),
    tier:           z.number().int().optional(),
    approval_token: ApprovalTokenSchema,
  }),

  // Tier 2 — approved with notification + veto window
  z.object({
    status:              z.literal('approved_with_notification'),
    decision_id:         z.string().uuid(),
    tier:                z.number().int().optional(),
    approval_token:      ApprovalTokenSchema,
    veto_window_seconds: z.number().int().positive(),
  }),

  // Tier 3 — pending human approval
  z.object({
    status:                z.literal('pending_human'),
    decision_id:           z.string().uuid(),
    tier:                  z.number().int().optional(),
    // Server-provided poll URL — use this, don't construct your own.
    poll_url:              z.string().min(1),
    poll_interval_seconds: z.number().int().positive(),
  }),

  // Denied — all tiers
  z.object({
    status:      z.literal('denied'),
    decision_id: z.string().uuid(),
    code:        z.string(),
    message:     z.string(),
  }),
]);

export type NotaryResponse = z.infer<typeof NotaryResponseSchema>;

// ── REQUEST TYPES ───────────────────────────────────────────────────────────

/** What the developer passes to sendTransaction(). */
export interface TxRequest {
  to:        `0x${string}`;
  value:     bigint;           // exact on-chain amount in wei
  /** Original calldata. Defaults to '0x' if omitted. */
  data?:     `0x${string}`;
  purpose:   string;           // must match policy.yaml allowed_purposes exactly
  amountUsd: number;           // USD equivalent for Notary spend limit checks
}

/** Internal — what the SDK sends to POST /v1/action-check. */
export interface ActionRequest {
  agent_id:    string;
  action:      string;
  destination: string;
  amount_usd:  number;
  amount_raw:  string;   // bigint as string — no float precision loss
  purpose:     string;
  chain_id:    number;
  nonce:       string;   // UUID v4 — fresh on every attempt, never reused
  timestamp:   string;   // ISO 8601 UTC
}

// ── CONFIG ──────────────────────────────────────────────────────────────────

export interface VerilockConfig {
  /** Notary URL — no trailing slash. e.g. http://localhost:8080 */
  notaryUrl: string;

  /** Bearer token from Notary startup log.
   *  SECURITY: never log this value. */
  agentToken: string;

  /** Registered agent ID in policy.yaml. e.g. "trading-bot-01" */
  agentId: string;

  /** Gnosis Safe address on Base that has VerilockGuard attached. */
  safeAddress: `0x${string}`;

  /** Safe owner private key — signs Safe transactions.
   *  SECURITY: never log this value. */
  ownerPrivateKey: `0x${string}`;

  // ── Optional behaviour ─────────────────────────────────────────────────

  /** true = Base mainnet (8453). Default: false = Base Sepolia (84532). */
  useMainnet?: boolean;

  /** Default purpose if not specified per-transaction. */
  defaultPurpose?: string;

  /** Seconds before expiry at which the SDK refuses to submit the token.
   *  Default: 10. Prevents the TTL race condition. */
  tokenExpiryBufferSeconds?: number;

  /** Milliseconds to wait for human approval before timeout. Default: 300_000. */
  humanApprovalTimeoutMs?: number;

  /** Milliseconds between human approval polls. Default: 3_000.
   *  Overridden by poll_interval_seconds from the server response. */
  humanApprovalPollIntervalMs?: number;

  /** Milliseconds before aborting a Notary HTTP request. Default: 10_000. */
  notaryTimeoutMs?: number;

  /** Max retry attempts on network failure. Default: 3. */
  maxRetries?: number;

  // ── Lifecycle callbacks ────────────────────────────────────────────────

  /** Fired when a transaction is awaiting human approval (Tier 3). */
  onPendingHumanApproval?: (decisionId: string) => void;

  /** Fired when a Tier 3 transaction is approved by a human. */
  onHumanApprovalReceived?: (decisionId: string) => void;

  /** Fired when a Tier 2 transaction executes with a notification sent.
   *  vetoWindowSeconds is how long until the veto window closes. */
  onApprovedWithNotification?: (decisionId: string, vetoWindowSeconds: number) => void;
}

// ── APPROVAL TOKEN ABI ──────────────────────────────────────────────────────
// ABI definition for ApprovalTokenData struct in VerilockGuard.sol.
// Field ORDER must exactly match the Solidity struct — used by viem's
// encodeAbiParameters in encoder.ts.

export const APPROVAL_TOKEN_ABI = [
  { name: 'tokenId',     type: 'bytes32' },
  { name: 'agentId',     type: 'string'  },
  { name: 'destination', type: 'address' },
  { name: 'amountRaw',   type: 'uint256' },
  { name: 'chainId',     type: 'uint256' },
  { name: 'nonce',       type: 'bytes32' },
  { name: 'expiresAt',   type: 'uint256' },
  { name: 'policyHash',  type: 'bytes32' },
  { name: 'signature',   type: 'bytes'   },
] as const;

// ── NETWORK CONSTANTS ───────────────────────────────────────────────────────

export const BASE_MAINNET_CHAIN_ID = 8453;
export const BASE_SEPOLIA_CHAIN_ID = 84532;

/**
 * 4-byte prefix marking the Verilock token in Safe tx data.
 * bytes4(keccak256("verilock.approval.v1")) truncated to 4 bytes.
 * No 0x prefix — raw hex, concatenated directly by encoder.ts.
 * Must match TOKEN_PREFIX in VerilockGuard.sol.
 */
export const VERILOCK_PREFIX = '544F4C47' as const;