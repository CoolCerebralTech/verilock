package policy

import "time"

// EngineStatus is the full health snapshot for the policy subsystem.
// Returned by the health endpoint — contains no secrets.
type EngineStatus struct {
	// Loader state
	PolicyVersion string    `json:"policy_version"` // empty if policy is invalid
	PolicyHash    string    `json:"policy_hash"`
	PolicyValid   bool      `json:"policy_valid"`
	AgentCount    int       `json:"agent_count"`
	LastReloadAt  time.Time `json:"last_reload_at"` // zero if never successfully loaded

	// Engine state
	DryRunMode bool `json:"dry_run_mode"`
}

// Status returns a full health snapshot of the policy engine.
// Called by the health endpoint — safe to return in HTTP responses.
func (e *Engine) Status(dryRun bool) EngineStatus {
	ls := e.loader.Status()
	return EngineStatus{
		PolicyVersion: ls.Version,
		PolicyHash:    ls.Hash,
		PolicyValid:   ls.Valid,
		AgentCount:    ls.AgentCount,
		LastReloadAt:  ls.LastReloadAt,
		DryRunMode:    dryRun,
	}
}

// LoaderStatus exposes raw loader state for the health endpoint.
// Returns (version, hash, isValid) — legacy helper kept for compatibility.
func (e *Engine) LoaderStatus() (version, hash string, valid bool) {
	p, h, v := e.loader.GetPolicy()
	if p == nil {
		return "", h, v
	}
	return p.Version, h, v
}
