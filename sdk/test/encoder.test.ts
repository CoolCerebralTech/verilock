/**
 * @file test/encoder.test.ts
 * Unit tests for the token encoder.
 *
 * CRITICAL CORRECTNESS NOTE:
 * uuidToBytes32 and stringToBytes32 use keccak256(toBytes(str)) to match
 * the Go Notary's encoding:
 *   Go:  gocrypto.Keccak256([]byte(str))
 *   TS:  keccak256(toBytes(str))
 *
 * The byte-exact fixture tests verify this encoding is stable.
 * If these tests fail after a dependency update, the on-chain verification
 * will also break — every transaction will revert with SignatureInvalid().
 */

import { describe, it, expect } from 'vitest';
import { keccak256, toBytes } from 'viem';
import {
  injectTollgateToken,
  hasTollgateToken,
  uuidToBytes32,
  stringToBytes32,
  findTollgatePrefixOffset,
} from '../src/encoder.js';
import { TOLLGATE_PREFIX } from '../src/types.js';
import type { ApprovalToken } from '../src/types.js';

// ── FIXTURE TOKEN ─────────────────────────────────────────────────────────────
// tier field is required by the updated ApprovalTokenSchema.

const FIXTURE_TOKEN: ApprovalToken = {
  token_id:       '123e4567-e89b-12d3-a456-426614174000',
  agent_id:       'trading-bot-01',
  policy_version: '1.0.0',
  policy_hash:    '0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890',
  tier:           1,
  auto_approved:  true,
  action:         'transfer',
  destination:    '0xDEF4560000000000000000000000000000000000',
  amount_usd:     10.00,
  amount_raw:     '10000000',
  purpose:        'defi_yield_optimization',
  chain_id:       84532,
  nonce:          'test-nonce-001',
  issued_at:      '2026-05-28T00:00:00.000Z',
  expires_at:     '2026-05-28T01:00:00.000Z',
  risk_score:     0.12,
  signature:      '0x' + 'ab'.repeat(65),
};

// ── uuidToBytes32 ─────────────────────────────────────────────────────────────

describe('uuidToBytes32', () => {
  it('produces a 0x-prefixed 64-char hex string (32 bytes)', () => {
    const result = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    expect(result).toMatch(/^0x[0-9a-f]{64}$/i);
  });

  it('is deterministic for the same input', () => {
    const a = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    const b = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    expect(a).toBe(b);
  });

  it('produces different output for different UUIDs', () => {
    const a = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    const b = uuidToBytes32('223e4567-e89b-12d3-a456-426614174001');
    expect(a).not.toBe(b);
  });

  it('matches keccak256(toBytes(uuid)) exactly — Go-compatible encoding', () => {
    // This is the ONLY correct encoding — must match Go's Keccak256([]byte(uuid)).
    // UUID is treated as a plain string (hyphens included) before hashing.
    const uuid     = '123e4567-e89b-12d3-a456-426614174000';
    const expected = keccak256(toBytes(uuid)); // compute inline — no hardcoded magic
    expect(uuidToBytes32(uuid)).toBe(expected);
  });

  it('includes hyphens in the hash input — NOT stripped', () => {
    // Stripping hyphens before hashing would produce a different value
    // from the Go Notary, breaking on-chain signature verification.
    const withHyphens    = uuidToBytes32('123e4567-e89b-12d3-a456-426614174000');
    const withoutHyphens = keccak256(toBytes('123e4567e89b12d3a456426614174000'));
    // These must be different — proves hyphens are included in the hash.
    expect(withHyphens).not.toBe(withoutHyphens);
  });
});

// ── stringToBytes32 ───────────────────────────────────────────────────────────

describe('stringToBytes32', () => {
  it('produces a 0x-prefixed 64-char hex string', () => {
    expect(stringToBytes32('test-nonce')).toMatch(/^0x[0-9a-f]{64}$/i);
  });

  it('is deterministic', () => {
    expect(stringToBytes32('abc')).toBe(stringToBytes32('abc'));
  });

  it('produces different output for different strings', () => {
    expect(stringToBytes32('nonce-1')).not.toBe(stringToBytes32('nonce-2'));
  });

  it('matches keccak256(toBytes(str)) exactly — Go-compatible encoding', () => {
    const str      = 'test-nonce-001';
    const expected = keccak256(toBytes(str));
    expect(stringToBytes32(str)).toBe(expected);
  });

  it('is NOT raw UTF-8 byte packing — produces keccak hash not raw bytes', () => {
    // Old (wrong) implementation: raw UTF-8 bytes padded to 64 hex chars.
    // Correct implementation: keccak256(toBytes(str))
    // These produce completely different results — verifies we didn't revert.
    const str    = 'test-nonce-001';
    const bytes  = new TextEncoder().encode(str);
    const rawHex = Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('')
      .padEnd(64, '0')
      .slice(0, 64);
    const rawPacked = `0x${rawHex}` as `0x${string}`;
    // The keccak256 result must differ from raw packing.
    expect(stringToBytes32(str)).not.toBe(rawPacked);
  });
});

// ── injectTollgateToken ───────────────────────────────────────────────────────

describe('injectTollgateToken', () => {
  it('output starts with 0x', () => {
    expect(injectTollgateToken('0x', FIXTURE_TOKEN)).toMatch(/^0x/);
  });

  it('output contains TOLLGATE_PREFIX 544F4C47', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(result.toLowerCase()).toContain(TOLLGATE_PREFIX.toLowerCase());
  });

  it('original calldata appears before the prefix', () => {
    const original = '0xdeadbeef';
    const result   = injectTollgateToken(original, FIXTURE_TOKEN);
    const hex      = result.slice(2).toLowerCase();
    const prefixIdx = hex.indexOf(TOLLGATE_PREFIX.toLowerCase());
    expect(hex.startsWith('deadbeef')).toBe(true);
    expect(prefixIdx).toBe(8); // 4 bytes of 'deadbeef' = 8 hex chars
  });

  it('works with empty original data 0x — prefix starts immediately', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(result.slice(2, 10).toLowerCase()).toBe(TOLLGATE_PREFIX.toLowerCase());
  });

  it('accepts undefined originalData — defaults to 0x', () => {
    const withUndefined = injectTollgateToken(undefined, FIXTURE_TOKEN);
    const withEmpty     = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(withUndefined).toBe(withEmpty);
  });

  it('output is longer than prefix + min ABI encoding (288 bytes)', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    // 0x prefix (2) + 4-byte prefix (8 hex) + at least 288 bytes of ABI (576 hex)
    expect(result.length).toBeGreaterThan(2 + 8 + 576);
  });

  it('byte-exact: tokenId in encoded output is keccak256 of UUID string', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    const hex    = result.slice(2).toLowerCase();

    // Skip the 4-byte TOLLGATE_PREFIX (8 hex chars).
    // Next 32 bytes (64 hex chars) are the ABI head of the tuple — offset pointer.
    // The actual tokenId bytes32 starts at the beginning of the encoded data
    // after the offset pointers. For a fixed first field it's at offset 0 of the data.
    // We verify the encoded data contains the keccak256 of the token_id.
    const expectedTokenId = keccak256(toBytes(FIXTURE_TOKEN.token_id)).slice(2).toLowerCase();
    expect(hex).toContain(expectedTokenId);
  });

  it('byte-exact: nonce in encoded output is keccak256 of nonce string', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    const hex    = result.slice(2).toLowerCase();
    const expectedNonce = keccak256(toBytes(FIXTURE_TOKEN.nonce)).slice(2).toLowerCase();
    expect(hex).toContain(expectedNonce);
  });

  it('byte-exact: expiresAt in encoded output is Unix seconds', () => {
    const result = injectTollgateToken('0x', FIXTURE_TOKEN);
    const hex    = result.slice(2).toLowerCase();
    const expiresAtSec = BigInt(Math.floor(new Date(FIXTURE_TOKEN.expires_at).getTime() / 1000));
    const expectedHex  = expiresAtSec.toString(16).padStart(64, '0');
    expect(hex).toContain(expectedHex);
  });

  it('two calls with the same token produce identical output', () => {
    const a = injectTollgateToken('0x', FIXTURE_TOKEN);
    const b = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(a).toBe(b);
  });
});

// ── hasTollgateToken ──────────────────────────────────────────────────────────

describe('hasTollgateToken', () => {
  it('returns true for injected data', () => {
    const data = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(hasTollgateToken(data)).toBe(true);
  });

  it('returns false for plain calldata with no prefix', () => {
    expect(hasTollgateToken('0xdeadbeef')).toBe(false);
  });

  it('returns false for empty data', () => {
    expect(hasTollgateToken('0x')).toBe(false);
  });
});

// ── findTollgatePrefixOffset ──────────────────────────────────────────────────

describe('findTollgatePrefixOffset', () => {
  it('returns 0 when no original calldata', () => {
    const data = injectTollgateToken('0x', FIXTURE_TOKEN);
    expect(findTollgatePrefixOffset(data)).toBe(0);
  });

  it('returns correct byte offset when original calldata present', () => {
    const original = '0xdeadbeef'; // 4 bytes
    const data     = injectTollgateToken(original, FIXTURE_TOKEN);
    expect(findTollgatePrefixOffset(data)).toBe(4);
  });

  it('returns -1 for data with no prefix', () => {
    expect(findTollgatePrefixOffset('0xdeadbeef')).toBe(-1);
  });
});