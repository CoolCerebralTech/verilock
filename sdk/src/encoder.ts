/**
 * @file encoder.ts
 * injectVerilockToken — encodes an ApprovalToken into Safe transaction data.
 *
 * Output structure:
 *   [ original calldata ] + [ 544F4C47 ] + [ ABI-encoded ApprovalTokenData ]
 *
 * The Guard reads this by scanning backwards for 0x544F4C47, slicing
 * everything after it, and abi.decode-ing the result as ApprovalTokenData.
 *
 * ── CRITICAL: keccak256 encoding for bytes32 fields ────────────────────────
 *
 * The Go Notary builds the EIP-712 struct hash using keccak256 for dynamic
 * fields that map to bytes32 on-chain (tokenId and nonce):
 *
 *   tokenIDHash = keccak256([]byte(token.TokenID))   // UUID string → bytes32
 *   nonceHash   = keccak256([]byte(token.Nonce))     // nonce string → bytes32
 *
 * The Guard reconstructs these identically in _hashApprovalToken().
 * The SDK MUST use the same encoding — NOT raw UTF-8 bytes, NOT stripped hex.
 *
 * If the encoding differs by even one byte, ecrecover recovers a different
 * address and every transaction reverts with SignatureInvalid().
 */

import { encodeAbiParameters, keccak256, toBytes, toHex } from 'viem';
import { ApprovalToken, APPROVAL_TOKEN_ABI, VERILOCK_PREFIX } from './types.js';

// ── BYTES32 HELPERS ──────────────────────────────────────────────────────────

/**
 * Converts a string to bytes32 by keccak256-hashing its UTF-8 bytes.
 *
 * This matches the Go Notary's EIP-712 encoding exactly:
 *   go: gocrypto.Keccak256([]byte(str))  →  bytes32
 *   ts: keccak256(toBytes(str))          →  `0x${string}` (32 bytes)
 *
 * Used for:
 *   - tokenId  (UUID string → bytes32)
 *   - nonce    (nonce string → bytes32)
 *
 * DO NOT use raw UTF-8 packing or hex-stripping here — those produce
 * different values from what the Notary signed and the Guard verifies.
 */
export function stringToBytes32(str: string): `0x${string}` {
  // toBytes encodes as UTF-8 (same as Go's []byte(str)).
  // keccak256 produces the 32-byte hash — exactly what the Guard expects.
  return keccak256(toBytes(str));
}

/**
 * Converts a UUID v4 string to bytes32 via keccak256.
 *
 * UUIDs are treated as plain strings by the Go Notary — the full UUID
 * including hyphens is hashed, not parsed as raw bytes.
 *
 * e.g. "123e4567-e89b-12d3-a456-426614174000"
 *   → keccak256(UTF-8 bytes of that string)
 *   → 0x<32-byte hash>
 */
export function uuidToBytes32(uuid: string): `0x${string}` {
  return stringToBytes32(uuid);
}

/**
 * Converts a hex-encoded policy hash (already bytes32) to the `0x${string}`
 * type expected by viem's encodeAbiParameters.
 *
 * policyHash arrives from the Notary as a 0x-prefixed 32-byte hex string.
 * It is passed through as-is — no re-hashing.
 */
export function policyHashToBytes32(policyHash: string): `0x${string}` {
  if (!policyHash.startsWith('0x')) {
    return `0x${policyHash}` as `0x${string}`;
  }
  return policyHash as `0x${string}`;
}

// ── MAIN ENCODER ─────────────────────────────────────────────────────────────

/**
 * Encodes an ApprovalToken into the Safe transaction data field.
 *
 * Field order in encodeAbiParameters MUST match the Solidity struct
 * ApprovalTokenData in VerilockGuard.sol:
 *   bytes32 tokenId      ← keccak256(token_id string)
 *   string  agentId      ← raw string (ABI string encoding handles dynamic type)
 *   address destination  ← as-is
 *   uint256 amountRaw    ← BigInt(amount_raw)
 *   uint256 chainId      ← BigInt(chain_id)
 *   bytes32 nonce        ← keccak256(nonce string)
 *   uint256 expiresAt    ← Unix seconds as BigInt
 *   bytes32 policyHash   ← as-is (already a 32-byte hash from Notary)
 *   bytes   signature    ← as-is (65-byte ECDSA signature)
 *
 * @param originalData  Original calldata. Pass '0x' if no calldata.
 * @param token         ApprovalToken from the Notary response.
 * @returns             Modified data field for Safe.execTransaction().
 */
export function injectVerilockToken(
  originalData: `0x${string}` | undefined,
  token: ApprovalToken,
): `0x${string}` {
  // Default to empty calldata if not provided.
  const base = originalData ?? '0x';

  // tokenId: keccak256(UUID string) — matches Go's Keccak256([]byte(tokenID))
  const tokenIdBytes32 = uuidToBytes32(token.token_id);

  // nonce: keccak256(nonce string) — matches Go's Keccak256([]byte(token.Nonce))
  const nonceBytes32 = stringToBytes32(token.nonce);

  // expiresAt: Unix seconds (not milliseconds — block.timestamp is in seconds)
  const expiresAtUnix = BigInt(Math.floor(new Date(token.expires_at).getTime() / 1000));

  // policyHash: already a 32-byte hex hash from the Notary — pass through
  const policyHashBytes32 = policyHashToBytes32(token.policy_hash);

  const encoded = encodeAbiParameters(
    APPROVAL_TOKEN_ABI as Parameters<typeof encodeAbiParameters>[0],
    [
      tokenIdBytes32,                          // bytes32 — keccak256(token_id)
      token.agent_id,                          // string
      token.destination as `0x${string}`,      // address
      BigInt(token.amount_raw),                // uint256
      BigInt(token.chain_id),                  // uint256
      nonceBytes32,                            // bytes32 — keccak256(nonce)
      expiresAtUnix,                           // uint256
      policyHashBytes32,                       // bytes32
      token.signature as `0x${string}`,        // bytes
    ] as Parameters<typeof encodeAbiParameters<typeof APPROVAL_TOKEN_ABI>>[1],
  );

  // Concatenate: original(no 0x) + PREFIX(no 0x) + encoded(no 0x)
  const originalHex = strip0x(base);
  const encodedHex  = strip0x(encoded);

  return `0x${originalHex}${VERILOCK_PREFIX}${encodedHex}`;
}

// ── INSPECTION HELPERS ────────────────────────────────────────────────────────

/**
 * Returns true if data already contains a Verilock token.
 * Guards against double-injection.
 */
export function hasVerilockToken(data: `0x${string}`): boolean {
  return strip0x(data).toLowerCase().includes(VERILOCK_PREFIX.toLowerCase());
}

/**
 * Returns the byte offset of the Verilock prefix in data, or -1 if absent.
 * Useful for debugging encoding issues.
 */
export function findVerilockPrefixOffset(data: `0x${string}`): number {
  const hex    = strip0x(data).toLowerCase();
  const prefix = VERILOCK_PREFIX.toLowerCase();
  const idx    = hex.indexOf(prefix);
  return idx === -1 ? -1 : idx / 2; // nibble index → byte index
}

// ── PRIVATE ───────────────────────────────────────────────────────────────────

function strip0x(hex: string): string {
  return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
}