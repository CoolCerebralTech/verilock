package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// tokenVersion is the prefix embedded in every token string.
// Allows future algorithm rotation without breaking existing tokens:
// a v2 verifier can check the prefix and apply different logic.
const tokenVersion = "v1"

// maxTokenBytes is the maximum accepted length of a raw token string.
// Prevents a large payload from reaching base64 decode + JSON parse.
const maxTokenBytes = 4096

// tokenPayload is the JSON body of an agent token.
// Every field is required — a token missing any field is invalid.
type tokenPayload struct {
	AgentID   string `json:"agent_id"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	TokenID   string `json:"token_id"`
}

// AgentTokenClaims is returned by VerifyToken on success.
// The gateway uses AgentID and TokenID to enforce policy and revocation.
type AgentTokenClaims struct {
	AgentID   string
	TokenID   string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// IssueToken creates a new HMAC-SHA256 signed agent token valid for ttl duration.
//
// Format: v1.<base64url(payload)>.<base64url(HMAC-SHA256(payload, secret))>
//
// The version prefix allows future algorithm rotation without breaking existing
// tokens — a future verifier checks the prefix and applies the right logic.
//
// SECURITY: secretHex must come from the keyfile or AGENT_TOKEN_SECRET env var only.
// Never log or return the raw secret value.
func IssueToken(agentID, secretHex string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		return "", fmt.Errorf("agent: token TTL must be positive (got %s)", ttl)
	}

	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		return "", fmt.Errorf("agent: invalid token secret — must be hex-encoded")
	}

	now := time.Now().UTC()
	payload := tokenPayload{
		AgentID:   agentID,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
		TokenID:   uuid.New().String(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("agent: failed to marshal token payload: %w", err)
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := computeHMAC(encodedPayload, secretBytes)
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)

	return tokenVersion + "." + encodedPayload + "." + encodedSig, nil
}

// VerifyToken parses and validates an agent token string.
//
// Checks performed in order:
//  1. Length     — reject oversized inputs before any decoding
//  2. Version    — must start with "v1."
//  3. Format     — must be three dot-separated segments
//  4. Signature  — HMAC-SHA256 verified with constant-time comparison
//  5. Payload    — valid JSON, all required fields present
//  6. IssuedAt   — must be in the past (not a future-dated token)
//  7. Ordering   — IssuedAt must be strictly before ExpiresAt
//  8. Expiry     — token must not be expired
//
// SECURITY:
//   - Uses crypto/subtle.ConstantTimeCompare for signature verification.
//   - Payload is decoded only AFTER signature is verified.
//   - On failure, returns generic errors — never reveals which check failed.
func VerifyToken(tokenStr, secretHex string) (*AgentTokenClaims, error) {
	// CHECK 1: Length guard — before any allocations.
	if len(tokenStr) > maxTokenBytes {
		return nil, fmt.Errorf("agent: malformed token")
	}

	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("agent: invalid token secret configuration")
	}

	// CHECK 2: Version prefix.
	prefix := tokenVersion + "."
	if !strings.HasPrefix(tokenStr, prefix) {
		return nil, fmt.Errorf("agent: malformed token")
	}
	// Strip version prefix for further parsing.
	rest := tokenStr[len(prefix):]

	// CHECK 3: Format — must be exactly payload.sig after the version.
	parts := strings.SplitN(rest, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("agent: malformed token")
	}

	encodedPayload := parts[0]
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}

	// CHECK 4: Signature — constant-time HMAC comparison.
	// SECURITY: never use == for signature comparison. Timing attacks are real.
	// Payload is decoded only after this passes.
	expectedSig := computeHMAC(encodedPayload, secretBytes)
	if subtle.ConstantTimeCompare(providedSig, expectedSig) != 1 {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	// CHECK 5: Decode and parse payload — only after signature verified.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}
	if payload.AgentID == "" || payload.TokenID == "" ||
		payload.IssuedAt == "" || payload.ExpiresAt == "" {
		return nil, fmt.Errorf("agent: malformed token")
	}

	// CHECK 6: Parse IssuedAt — must not be in the future (allow 30s clock skew).
	issuedAt, err := time.Parse(time.RFC3339, payload.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}
	if issuedAt.After(time.Now().UTC().Add(30 * time.Second)) {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	// CHECK 7: Parse ExpiresAt — must be strictly after IssuedAt.
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}
	if !expiresAt.After(issuedAt) {
		return nil, fmt.Errorf("agent: malformed token")
	}

	// CHECK 8: Expiry.
	if time.Now().UTC().After(expiresAt) {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	return &AgentTokenClaims{
		AgentID:   payload.AgentID,
		TokenID:   payload.TokenID,
		IssuedAt:  issuedAt,
		ExpiresAt: expiresAt,
	}, nil
}

// computeHMAC returns the HMAC-SHA256 of message using key.
func computeHMAC(message string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}
