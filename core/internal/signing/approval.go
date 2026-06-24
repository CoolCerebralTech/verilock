package signing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gocrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

// ApprovalToken is the signed artifact Verilock returns on a successful evaluation.
// The Guard smart contract verifies the Signature field on-chain using ecrecover
// to confirm Verilock approved this exact transaction payload.
//
// SECURITY: Every field that is signed is also returned in the token so the
// Guard — and any auditor — can independently verify the signature covers
// exactly what was approved. Nothing is hidden.
type ApprovalToken struct {
	// Identity
	TokenID       string `json:"token_id"` // UUID v4 — unique per token
	AgentID       string `json:"agent_id"`
	PolicyVersion string `json:"policy_version"` // exact policy version that approved this
	PolicyHash    string `json:"policy_hash"`    // keccak256 of policy.yaml at decision time

	// Approval path
	Tier         int  `json:"tier"`          // 1 | 2 | 3 — which tier produced this token
	AutoApproved bool `json:"auto_approved"` // true if Tier 1 (no human involved)

	// What was approved
	Action      string  `json:"action"`
	Destination string  `json:"destination"`
	AmountUSD   float64 `json:"amount_usd"`
	AmountRaw   string  `json:"amount_raw"` // exact on-chain amount as string (no float precision loss)
	Purpose     string  `json:"purpose"`
	ChainID     int64   `json:"chain_id"` // 84532 = Base Sepolia, 8453 = Base mainnet
	Nonce       string  `json:"nonce"`    // nonce from the original request

	// Timing — critical for replay prevention
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"` // IssuedAt + TTL from config

	// Risk metadata
	RiskScore float64 `json:"risk_score"` // 0.0–1.0 behavioural baseline score

	// Cryptographic proof — what the Guard verifies on-chain
	Signature string `json:"signature"` // hex-encoded 65-byte ECDSA sig over EIP-712 hash
}

// BuildRequest carries all inputs needed to construct and sign an ApprovalToken.
type BuildRequest struct {
	AgentID       string
	PolicyVersion string
	PolicyHash    string
	Tier          int
	AutoApproved  bool
	Action        string
	Destination   string
	AmountUSD     float64
	AmountRaw     string
	Purpose       string
	ChainID       int64
	Nonce         string

	// TTLSeconds is the token lifetime. The token will be refused if the
	// resulting ExpiresAt is less than MinRemainingSeconds from now —
	// protecting against the race condition where a token is issued but
	// expires before the Safe can execute.
	TTLSeconds          int
	MinRemainingSeconds int // from config.ApprovalTokenMinRemainingSeconds

	RiskScore float64
}

// BuildApprovalToken constructs an ApprovalToken, computes its EIP-712 hash,
// signs it with Verilock's ECDSA key, and returns the complete signed token.
//
// Returns an error if:
//   - The resulting token would expire within MinRemainingSeconds (TTL race condition)
//   - The amountRaw cannot be parsed as a decimal integer
//   - The policyHash is not valid hex
//   - The ECDSA signing operation fails
func (s *Signer) BuildApprovalToken(req BuildRequest) (*ApprovalToken, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(req.TTLSeconds) * time.Second)

	// ── TTL minimum-remaining check ───────────────────────────────────────────
	// Refuse to issue a token that would expire before the SDK can submit it to
	// the Safe. This prevents the Tier 3 race condition: human approves at
	// second 58 of a 60s window, token issued, Safe submission times out.
	remaining := time.Until(expiresAt)
	minRemaining := time.Duration(req.MinRemainingSeconds) * time.Second
	if remaining < minRemaining {
		return nil, fmt.Errorf(
			"signing: token TTL too short to issue safely — %s remaining, minimum is %s; "+
				"the caller should request a fresh token with a full TTL",
			remaining.Round(time.Second), minRemaining,
		)
	}

	tokenID := uuid.New().String()

	token := &ApprovalToken{
		TokenID:       tokenID,
		AgentID:       req.AgentID,
		PolicyVersion: req.PolicyVersion,
		PolicyHash:    req.PolicyHash,
		Tier:          req.Tier,
		AutoApproved:  req.AutoApproved,
		Action:        req.Action,
		Destination:   req.Destination,
		AmountUSD:     req.AmountUSD,
		AmountRaw:     req.AmountRaw,
		Purpose:       req.Purpose,
		ChainID:       req.ChainID,
		Nonce:         req.Nonce,
		IssuedAt:      now,
		ExpiresAt:     expiresAt,
		RiskScore:     req.RiskScore,
	}

	// Compute the EIP-712 hash over the token fields.
	// The Guard contract's verifyingContract address is embedded in the domain
	// separator — this is what binds the signature to the deployed Guard.
	hash, err := s.eip712Hash(token)
	if err != nil {
		return nil, fmt.Errorf("signing: EIP-712 hash failed: %w", err)
	}

	sig, err := s.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("signing: token signing failed: %w", err)
	}

	token.Signature = "0x" + hex.EncodeToString(sig)
	return token, nil
}

// ── EIP-712 Implementation ────────────────────────────────────────────────────
//
// EIP-712 structured data hashing pipeline:
//
//   finalHash = keccak256(0x1901 ‖ domainSeparatorHash ‖ structHash(ApprovalToken))
//
// The domain separator binds the hash to this contract address and chain ID,
// preventing cross-domain and cross-chain replay attacks.
//
// The struct hash ABI-encodes typed fields in the exact order defined in the
// type string — the Guard contract uses the identical encoding for ecrecover.
//
// LOCKED: Field ordering and types in the type string must match the Guard
// contract's ApprovalTokenData struct exactly. Changing them breaks on-chain
// verification without a contract redeployment.

// typeHashOnce ensures type hash vars are computed exactly once, safely.
// Using sync.Once avoids the package-level var init order issue where
// gocrypto may not be fully initialised when the var block runs.
var (
	typeHashOnce         sync.Once
	cachedDomainTypeHash []byte
	cachedStructTypeHash []byte
)

func initTypeHashes() {
	typeHashOnce.Do(func() {
		cachedDomainTypeHash = gocrypto.Keccak256(
			[]byte("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
		)
		cachedStructTypeHash = gocrypto.Keccak256(
			[]byte("ApprovalToken(bytes32 tokenId,string agentId,address destination,uint256 amountRaw,uint256 chainId,bytes32 nonce,uint256 expiresAt,bytes32 policyHash)"),
		)
	})
}

// eip712Hash computes the final EIP-712 hash for the given token.
// The domain separator uses s.guardContractAddress — the actual deployed Guard.
// This is the 32-byte value that gets signed with ECDSA.
func (s *Signer) eip712Hash(token *ApprovalToken) ([]byte, error) {
	initTypeHashes()

	chainID := big.NewInt(token.ChainID)

	// ── Domain Separator ──────────────────────────────────────────────────────
	// verifyingContract = s.guardContractAddress (the deployed VerilockGuard).
	// This binding is what prevents a Notary signature from being replayed
	// against a different Guard contract on any chain.
	domainSeparator := gocrypto.Keccak256(
		concat(
			cachedDomainTypeHash,
			gocrypto.Keccak256([]byte("Verilock")), // name
			gocrypto.Keccak256([]byte("1")),        // version
			padUint256Must(chainID),                // chainId
			padAddress(s.guardContractAddress),     // verifyingContract — the real Guard address
		),
	)

	// ── Struct Hash ───────────────────────────────────────────────────────────
	// Pack each field in the exact type and order defined in cachedStructTypeHash.
	// The Guard contract must use the identical ABI encoding.

	// tokenId: bytes32 — UUID string → keccak256 → bytes32
	tokenIDHash := gocrypto.Keccak256([]byte(token.TokenID))

	// agentId: string — EIP-712 encodes dynamic types as keccak256 of content
	agentIDHash := gocrypto.Keccak256([]byte(token.AgentID))

	// destination: address → padded to 32 bytes
	dest := common.HexToAddress(token.Destination)

	// amountRaw: uint256 — parse from string to avoid float64 precision loss
	amountRaw := new(big.Int)
	if _, ok := amountRaw.SetString(token.AmountRaw, 10); !ok {
		return nil, fmt.Errorf("invalid amountRaw %q — must be a decimal integer string (wei value)", token.AmountRaw)
	}
	amountRawPadded, err := padUint256(amountRaw)
	if err != nil {
		return nil, fmt.Errorf("amountRaw exceeds uint256 range: %w", err)
	}

	// nonce: bytes32 — keccak256 of nonce string
	nonceHash := gocrypto.Keccak256([]byte(token.Nonce))

	// expiresAt: uint256 — Unix seconds (not milliseconds — Guard uses block.timestamp)
	expiresAt := big.NewInt(token.ExpiresAt.Unix())

	// policyHash: bytes32 — decode from hex string
	policyHashBytes, err := hexToBytes32(token.PolicyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid policyHash: %w", err)
	}

	structHash := gocrypto.Keccak256(
		concat(
			cachedStructTypeHash,
			tokenIDHash,               // bytes32
			agentIDHash,               // bytes32 (keccak256 of string)
			padAddress(dest),          // address → 32 bytes
			amountRawPadded,           // uint256
			padUint256Must(chainID),   // uint256
			nonceHash,                 // bytes32
			padUint256Must(expiresAt), // uint256
			policyHashBytes[:],        // bytes32
		),
	)

	// ── Final Hash ────────────────────────────────────────────────────────────
	// keccak256(0x1901 ‖ domainSeparator ‖ structHash)
	// 0x1901 is the EIP-712 magic prefix — required by the standard.
	finalHash := gocrypto.Keccak256(
		concat(
			[]byte{0x19, 0x01},
			domainSeparator,
			structHash,
		),
	)

	return finalHash, nil
}

// VerifyToken re-derives the EIP-712 hash from the token fields and verifies
// that the signature was produced by expectedAddress.
//
// Used in tests and the startup canary check — not in the hot request path.
// The Guard contract does its own on-chain verification; this is the Go mirror.
func VerifyToken(token *ApprovalToken, guardAddress, expectedAddress string) (bool, error) {
	// Construct a temporary Signer with the Guard address so we can call eip712Hash.
	// We don't need a real private key — we're only computing the hash.
	s := &Signer{
		guardContractAddress: common.HexToAddress(guardAddress),
	}

	hash, err := s.eip712Hash(token)
	if err != nil {
		return false, fmt.Errorf("signing: VerifyToken hash failed: %w", err)
	}

	sigBytes, err := hex.DecodeString(stripHexPrefix(token.Signature))
	if err != nil {
		return false, fmt.Errorf("signing: invalid signature hex: %w", err)
	}
	if len(sigBytes) != 65 {
		return false, fmt.Errorf("signing: signature must be 65 bytes, got %d", len(sigBytes))
	}

	// Validate V before adjusting — must be exactly 27 or 28 (Ethereum standard).
	// Anything else is a malformed token, not a verification failure.
	v := sigBytes[64]
	if v != 27 && v != 28 {
		return false, fmt.Errorf(
			"signing: invalid signature V byte %d — must be 27 or 28 (Ethereum standard)",
			v,
		)
	}

	sigCopy := make([]byte, 65)
	copy(sigCopy, sigBytes)
	sigCopy[64] -= 27 // adjust back to recovery ID (0 or 1) for SigToPub

	pubKey, err := gocrypto.SigToPub(hash, sigCopy)
	if err != nil {
		return false, fmt.Errorf("signing: public key recovery failed: %w", err)
	}

	recoveredAddress := gocrypto.PubkeyToAddress(*pubKey).Hex()
	return strings.EqualFold(recoveredAddress, expectedAddress), nil
}

// ── ABI encoding helpers ──────────────────────────────────────────────────────

// padUint256 encodes a *big.Int as a 32-byte big-endian ABI uint256.
// Returns an error if the value exceeds 32 bytes (> 2²⁵⁶-1).
func padUint256(n *big.Int) ([]byte, error) {
	nb := n.Bytes()
	if len(nb) > 32 {
		return nil, fmt.Errorf("value %s exceeds uint256 range (%d bytes > 32)", n.String(), len(nb))
	}
	b := make([]byte, 32)
	copy(b[32-len(nb):], nb)
	return b, nil
}

// padUint256Must is padUint256 for values that are guaranteed in range
// (chain IDs, timestamps, TTLs). Panics on overflow — caller is responsible
// for ensuring the value is within uint256 range before calling.
func padUint256Must(n *big.Int) []byte {
	b, err := padUint256(n)
	if err != nil {
		panic("signing: padUint256Must called with out-of-range value: " + err.Error())
	}
	return b
}

// padAddress encodes an Ethereum address as a 32-byte ABI word (left-zero-padded).
func padAddress(addr common.Address) []byte {
	b := make([]byte, 32)
	copy(b[12:], addr.Bytes()) // address is 20 bytes; 12 leading zeros pad to 32
	return b
}

// hexToBytes32 decodes a hex string (with or without 0x prefix) into [32]byte.
// Right-aligns the decoded bytes — matching ABI encoding for bytes32.
func hexToBytes32(h string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(stripHexPrefix(h))
	if err != nil {
		return out, fmt.Errorf("invalid hex string: %w", err)
	}
	if len(b) > 32 {
		return out, fmt.Errorf("hex value exceeds 32 bytes (got %d)", len(b))
	}
	copy(out[32-len(b):], b)
	return out, nil
}

// stripHexPrefix removes a leading "0x" or "0X" prefix if present.
func stripHexPrefix(s string) string {
	if len(s) >= 2 && (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		return s[2:]
	}
	return s
}

// concat joins multiple byte slices into one with a single allocation.
func concat(slices ...[]byte) []byte {
	total := 0
	for _, s := range slices {
		total += len(s)
	}
	out := make([]byte, 0, total)
	for _, s := range slices {
		out = append(out, s...)
	}
	return out
}
