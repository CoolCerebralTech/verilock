package policy

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	gocrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Loader reads policy.yaml and keeps an in-memory copy that is atomically
// updated whenever the file changes on disk.
//
// SECURITY CONTRACT:
//   - If the policy file cannot be read or parsed at any point, all requests
//     are denied until the file is restored. The Loader never serves a stale
//     or partial policy.
//   - The active policy, its hash, and its valid flag are updated atomically
//     under a write lock. A request mid-evaluation always sees a fully
//     consistent policy.
//   - The policy hash is keccak256 of the raw file bytes — exactly what is
//     embedded in every ApprovalToken and audit record.
type Loader struct {
	mu           sync.RWMutex
	policy       *Policy
	policyHash   string    // keccak256 hex of raw policy.yaml bytes
	policyValid  bool      // false = deny all requests
	lastReloadAt time.Time // time of last successful load (zero = never loaded)
	filePath     string
	log          *zap.Logger
	cancel       context.CancelFunc
}

// LoaderStatus is the snapshot returned by the health endpoint.
type LoaderStatus struct {
	Version      string
	Hash         string
	Valid        bool
	AgentCount   int
	LastReloadAt time.Time
	WatcherAlive bool // true if hot-reload goroutine is running
}

// NewLoader creates a Loader, performs the initial policy load, and optionally
// starts a file watcher for hot reload.
//
// Returns an error only if the initial load fails — a server with no valid
// policy at startup cannot serve any requests safely, so this is fatal.
func NewLoader(filePath string, hotReload bool, log *zap.Logger) (*Loader, error) {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Loader{
		filePath: filePath,
		log:      log,
		cancel:   cancel,
	}

	if err := l.load(); err != nil {
		cancel()
		return nil, fmt.Errorf("policy: initial load failed: %w", err)
	}

	if hotReload {
		go l.watchFile(ctx)
	}

	return l, nil
}

// Close stops the file watcher goroutine. Called during graceful shutdown.
func (l *Loader) Close() {
	l.cancel()
}

// GetPolicy returns the current active policy and its keccak256 hash.
// Returns (nil, "", false) if the policy is unavailable — caller must deny all requests.
func (l *Loader) GetPolicy() (*Policy, string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policy, l.policyHash, l.policyValid
}

// Status returns a snapshot of the current loader state for the health endpoint.
func (l *Loader) Status() LoaderStatus {
	l.mu.RLock()
	defer l.mu.RUnlock()

	s := LoaderStatus{
		Hash:         l.policyHash,
		Valid:        l.policyValid,
		LastReloadAt: l.lastReloadAt,
	}
	if l.policy != nil {
		s.Version = l.policy.Version
		s.AgentCount = len(l.policy.Agents)
	}
	return s
}

// load reads policy.yaml from disk, parses and validates it, then atomically
// replaces the in-memory policy. On any failure, marks policy as invalid.
func (l *Loader) load() error {
	raw, err := os.ReadFile(l.filePath)
	if err != nil {
		l.mu.Lock()
		l.policyValid = false
		l.mu.Unlock()
		return fmt.Errorf("cannot read policy file %q: %w", l.filePath, err)
	}

	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		l.mu.Lock()
		l.policyValid = false
		l.mu.Unlock()
		return fmt.Errorf("cannot parse policy YAML: %w", err)
	}

	if err := validatePolicy(&p); err != nil {
		l.mu.Lock()
		l.policyValid = false
		l.mu.Unlock()
		return fmt.Errorf("policy validation failed: %w", err)
	}

	// keccak256 of raw bytes — embedded in every ApprovalToken and audit record.
	hash := fmt.Sprintf("0x%x", gocrypto.Keccak256(raw))
	now := time.Now().UTC()

	l.mu.Lock()
	l.policy = &p
	l.policyHash = hash
	l.policyValid = true
	l.lastReloadAt = now
	l.mu.Unlock()

	l.log.Info("policy loaded",
		zap.String("version", p.Version),
		zap.String("hash", hash),
		zap.String("updated_by", p.UpdatedBy),
		zap.Int("agent_count", len(p.Agents)),
	)

	return nil
}

// watchFile uses fsnotify to hot-reload policy.yaml on change.
// Exits cleanly when ctx is cancelled (i.e. when Close() is called).
//
// SECURITY: if a reload fails (bad YAML, validation error), the previous
// valid policy remains active. The server logs a critical error but does not
// crash — operators can fix the file and it will reload automatically.
func (l *Loader) watchFile(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		l.log.Error("policy: failed to start file watcher", zap.Error(err))
		return
	}
	defer watcher.Close()

	if err := watcher.Add(l.filePath); err != nil {
		l.log.Error("policy: failed to watch file",
			zap.String("path", l.filePath), zap.Error(err))
		return
	}

	l.log.Info("policy: hot reload active", zap.String("watching", l.filePath))

	for {
		select {
		case <-ctx.Done():
			l.log.Info("policy: file watcher stopped")
			return

		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// React to writes and renames — editors like vim write via rename/create.
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				l.log.Info("policy: file changed — reloading",
					zap.String("event", event.Op.String()))
				if err := l.load(); err != nil {
					l.log.Error("policy: reload FAILED — previous policy remains active",
						zap.Error(err))
				}
				// Re-add after rename events, which can cause inode tracking to break.
				_ = watcher.Add(l.filePath)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			l.log.Error("policy: file watcher error", zap.Error(err))
		}
	}
}

// validatePolicy checks that the policy is internally consistent and complete.
// Called after every YAML parse — before the policy is made active.
func validatePolicy(p *Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy must have a version field")
	}
	if p.Global.DefaultAction != "deny" {
		return fmt.Errorf(
			"global_rules.default_action must be 'deny' (got %q) — fail-closed is mandatory",
			p.Global.DefaultAction,
		)
	}
	if p.Global.MaxRequestAgeSeconds <= 0 {
		return fmt.Errorf("global_rules.max_request_age_seconds must be positive")
	}
	if p.Global.NonceWindowSeconds <= 0 {
		return fmt.Errorf("global_rules.nonce_window_seconds must be positive")
	}
	if len(p.Agents) == 0 {
		return fmt.Errorf("policy must define at least one agent")
	}

	seenIDs := make(map[string]bool)
	for i, agent := range p.Agents {
		prefix := fmt.Sprintf("agent[%d] %q", i, agent.ID)

		if agent.ID == "" {
			return fmt.Errorf("agent[%d] has no id field", i)
		}
		if seenIDs[agent.ID] {
			return fmt.Errorf("duplicate agent id %q — each agent must have a unique id", agent.ID)
		}
		seenIDs[agent.ID] = true

		// ── Spend limits ──────────────────────────────────────────────────────

		if agent.SpendLimits.MaxPerTransactionUSD <= 0 {
			return fmt.Errorf("%s: max_per_transaction_usd must be positive", prefix)
		}
		if agent.SpendLimits.MaxPerHourUSD <= 0 {
			return fmt.Errorf("%s: max_per_hour_usd must be positive", prefix)
		}
		if agent.SpendLimits.MaxPerDayUSD <= 0 {
			return fmt.Errorf("%s: max_per_day_usd must be positive", prefix)
		}
		if agent.SpendLimits.AutoApproveBelowUSD < 0 {
			return fmt.Errorf("%s: auto_approve_below_usd cannot be negative", prefix)
		}
		if agent.SpendLimits.RequireHumanAboveUSD <= 0 {
			return fmt.Errorf("%s: require_human_above_usd must be positive", prefix)
		}

		// Three-tier threshold ordering: AutoApprove <= RequireHuman <= MaxPerTransaction.
		// Inverted thresholds would silently collapse Tier 2 or Tier 3.
		if agent.SpendLimits.AutoApproveBelowUSD > agent.SpendLimits.RequireHumanAboveUSD {
			return fmt.Errorf(
				"%s: auto_approve_below_usd ($%.2f) must be <= require_human_above_usd ($%.2f)",
				prefix,
				agent.SpendLimits.AutoApproveBelowUSD,
				agent.SpendLimits.RequireHumanAboveUSD,
			)
		}
		if agent.SpendLimits.RequireHumanAboveUSD > agent.SpendLimits.MaxPerTransactionUSD {
			return fmt.Errorf(
				"%s: require_human_above_usd ($%.2f) must be <= max_per_transaction_usd ($%.2f)",
				prefix,
				agent.SpendLimits.RequireHumanAboveUSD,
				agent.SpendLimits.MaxPerTransactionUSD,
			)
		}

		// ── Behavioral thresholds ─────────────────────────────────────────────

		if agent.BehavioralRiskThreshold < 0 || agent.BehavioralRiskThreshold > 1.0 {
			return fmt.Errorf("%s: behavioral_risk_threshold must be between 0.0 and 1.0", prefix)
		}
		if agent.BehavioralReviewThreshold < 0 || agent.BehavioralReviewThreshold > 1.0 {
			return fmt.Errorf("%s: behavioral_review_threshold must be between 0.0 and 1.0", prefix)
		}
		// Review must trigger before block — otherwise it's never reached.
		if agent.BehavioralReviewThreshold >= agent.BehavioralRiskThreshold {
			return fmt.Errorf(
				"%s: behavioral_review_threshold (%.2f) must be < behavioral_risk_threshold (%.2f)",
				prefix,
				agent.BehavioralReviewThreshold,
				agent.BehavioralRiskThreshold,
			)
		}

		// ── Purposes ─────────────────────────────────────────────────────────

		if len(agent.AllowedPurposes) == 0 {
			return fmt.Errorf("%s: allowed_purposes cannot be empty", prefix)
		}

		// ── Cold-start ────────────────────────────────────────────────────────

		if agent.MinDataPointsForAutoApprove < 0 {
			return fmt.Errorf("%s: min_data_points_for_auto_approve cannot be negative", prefix)
		}
	}

	return nil
}
