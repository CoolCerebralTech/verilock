package agent

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

// RevocationStore is implemented by the audit DB.
// The registry uses it to persist revocations across restarts.
type RevocationStore interface {
	WriteRevocation(tokenID, agentID, reason string) error
	// LoadAllRevocations loads revoked token IDs active within the last maxAgeDays.
	// Tokens older than the max token TTL are irrelevant — the Guard rejects them by TTL.
	LoadAllRevocations(maxAgeDays int) (map[string]bool, error)
}

// Registry manages agent token revocations and provides agent validation helpers.
//
// SECURITY CONTRACT:
//   - Revocation list is in-memory for sub-millisecond checks on every request.
//   - Revocations are also persisted to SQLite so they survive server restarts.
//   - On startup, all active revocations are loaded from SQLite into memory.
//   - IsRevoked() is checked on every request, after signature verification.
//   - secretHex is held in memory only — never logged, never serialized.
//   - Close() zeros secretHex in memory before the Registry is released.
type Registry struct {
	mu        sync.RWMutex
	revoked   map[string]bool // tokenID → true
	store     RevocationStore
	secretHex string // AGENT_TOKEN_SECRET — never log this field
	log       *zap.Logger
}

// NewRegistry creates a Registry, loads existing revocations from the store,
// and returns a ready-to-use Registry or a fatal error.
//
// maxRevocationAgeDays controls how far back revocations are loaded.
// Pass the max token lifetime in days (e.g. 30 for 30-day tokens).
// Revocations older than this are irrelevant — those tokens have already expired.
func NewRegistry(store RevocationStore, secretHex string, maxRevocationAgeDays int, log *zap.Logger) (*Registry, error) {
	r := &Registry{
		revoked:   make(map[string]bool),
		store:     store,
		secretHex: secretHex,
		log:       log,
	}

	// Load active revocations from SQLite into memory.
	existing, err := store.LoadAllRevocations(maxRevocationAgeDays)
	if err != nil {
		return nil, fmt.Errorf("agent: failed to load revocations from store: %w", err)
	}
	r.revoked = existing

	log.Info("agent registry initialized",
		zap.Int("revoked_tokens_loaded", len(existing)),
	)

	return r, nil
}

// Close zeros the HMAC secret in memory. Call during graceful shutdown.
// After Close(), IssueToken and Verify will fail — do not call them after Close().
func (r *Registry) Close() {
	// Zero the secret string's backing bytes.
	b := []byte(r.secretHex)
	for i := range b {
		b[i] = 0
	}
	r.secretHex = ""
}

// IsRevoked reports whether tokenID has been revoked.
// Called on every request — must be fast (single map lookup under RLock).
func (r *Registry) IsRevoked(tokenID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revoked[tokenID]
}

// RevokeToken adds tokenID to the in-memory revocation list and persists it
// to SQLite. Effect is immediate — under 1ms.
//
// SECURITY: SQLite write happens first. If it fails, in-memory state is NOT
// updated — a failed persist would lose the revocation on restart.
func (r *Registry) RevokeToken(tokenID, agentID, reason string) error {
	if err := r.store.WriteRevocation(tokenID, agentID, reason); err != nil {
		return fmt.Errorf("agent: failed to persist revocation for token %s: %w", tokenID, err)
	}

	r.mu.Lock()
	r.revoked[tokenID] = true
	r.mu.Unlock()

	r.log.Warn("agent token revoked",
		zap.String("token_id", tokenID),
		zap.String("agent_id", agentID),
		zap.String("reason", reason),
	)

	return nil
}

// Verify parses and validates a raw token string.
// Checks (in order): signature, expiry, IssuedAt ordering, revocation.
// Returns claims on success, generic error on any failure.
//
// SECURITY: Error messages are intentionally generic — never reveal which
// check failed. The 401 response to the client must be equally generic.
func (r *Registry) Verify(tokenStr string) (*AgentTokenClaims, error) {
	claims, err := VerifyToken(tokenStr, r.secretHex)
	if err != nil {
		// Do not wrap — VerifyToken errors are already generic.
		return nil, err
	}

	// Check revocation AFTER signature verification.
	// Checking before signature would allow timing-based enumeration of
	// revoked token IDs by observing whether the revocation map is hit.
	if r.IsRevoked(claims.TokenID) {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	return claims, nil
}

// IssueToken creates a new signed agent token for agentID valid for ttl.
// Used by admin tooling and the setup command — not called in the hot request path.
//
// Recommended TTLs:
//   - Development:  30 * 24 * time.Hour  (30 days)
//   - Production:   7 * 24 * time.Hour   (7 days — rotate more frequently)
func (r *Registry) IssueToken(agentID string, ttl time.Duration) (string, error) {
	token, err := IssueToken(agentID, r.secretHex, ttl)
	if err != nil {
		return "", fmt.Errorf("agent: IssueToken failed: %w", err)
	}
	return token, nil
}
