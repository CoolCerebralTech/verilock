package policy

import "time"

// Policy is the top-level structure of policy.yaml.
// Every field maps directly to a YAML key — no magic, no inference.
type Policy struct {
	Version   string        `yaml:"version"`
	UpdatedAt string        `yaml:"updated_at"`
	UpdatedBy string        `yaml:"updated_by"`
	Global    GlobalRules   `yaml:"global_rules"`
	Agents    []AgentPolicy `yaml:"agents"`
}

// GlobalRules apply to every request regardless of which agent sends it.
// These are the floor — no per-agent policy can override them.
type GlobalRules struct {
	DefaultAction        string `yaml:"default_action"`          // must be "deny"
	MaxRequestAgeSeconds int    `yaml:"max_request_age_seconds"` // reject stale requests
	RequireNonce         bool   `yaml:"require_nonce"`
	NonceWindowSeconds   int    `yaml:"nonce_window_seconds"`
}

// AgentPolicy defines all rules for a single registered AI agent.
// An agent not listed here is ALWAYS denied — there is no default policy.
type AgentPolicy struct {
	ID             string `yaml:"id"`
	Name           string `yaml:"name"`
	Enabled        bool   `yaml:"enabled"`
	Purpose        string `yaml:"purpose"`
	ClearanceLevel int    `yaml:"clearance_level"` // 1 = lowest, 5 = highest

	SpendLimits         SpendLimits `yaml:"spend_limits"`
	AllowedDestinations []string    `yaml:"allowed_destinations"`
	BlockedDestinations []string    `yaml:"blocked_destinations"`
	AllowedPurposes     []string    `yaml:"allowed_purposes"`

	RejectUnsolicitedPermissions bool `yaml:"reject_unsolicited_permissions"`

	// Behavioral baseline thresholds — both in the 0.0–1.0 range.
	// review_threshold must be < risk_threshold (validated at load time).
	// Scores above risk_threshold → DENIED (CodeBehavioralAnomaly).
	// Scores above review_threshold but below risk_threshold → approved but FlaggedReview=true.
	BehavioralRiskThreshold   float64 `yaml:"behavioral_risk_threshold"`   // block above this
	BehavioralReviewThreshold float64 `yaml:"behavioral_review_threshold"` // flag above this

	// MinDataPointsForAutoApprove is the number of approved transactions the
	// baseline engine must have seen before this agent is eligible for Tier 1
	// auto-approval. New agents default to Tier 3 (human approval) until warm.
	// Set to 0 to disable the cold-start protection (not recommended).
	MinDataPointsForAutoApprove int `yaml:"min_data_points_for_auto_approve"`
}

// SpendLimits defines all monetary boundaries for an agent.
//
// Three-tier routing uses three thresholds:
//
//	Tier 1 (auto-approve):   amount <= AutoApproveBelowUSD
//	Tier 2 (notify + veto):  AutoApproveBelowUSD < amount <= RequireHumanAboveUSD
//	Tier 3 (human approval): amount > RequireHumanAboveUSD
//
// Invariant enforced at load time:
//
//	0 < AutoApproveBelowUSD <= RequireHumanAboveUSD <= MaxPerTransactionUSD
type SpendLimits struct {
	MaxPerTransactionUSD float64 `yaml:"max_per_transaction_usd"`
	MaxPerHourUSD        float64 `yaml:"max_per_hour_usd"`
	MaxPerDayUSD         float64 `yaml:"max_per_day_usd"`

	// AutoApproveBelowUSD is the Tier 1 ceiling.
	// Transactions at or below this amount are auto-approved (no human involved).
	AutoApproveBelowUSD float64 `yaml:"auto_approve_below_usd"`

	// RequireHumanAboveUSD is the Tier 3 floor.
	// Transactions above this amount require explicit human approval.
	// Transactions between AutoApproveBelowUSD and RequireHumanAboveUSD are Tier 2.
	RequireHumanAboveUSD float64 `yaml:"require_human_above_usd"`
}

// ActionRequest is the validated, parsed financial action request from an AI agent.
// Every field is required. The gateway layer rejects requests with any missing
// field before this struct is constructed.
type ActionRequest struct {
	AgentID     string    `json:"agent_id"`
	Action      string    `json:"action"`
	Destination string    `json:"destination"`
	AmountUSD   float64   `json:"amount_usd"`
	AmountRaw   string    `json:"amount_raw"` // exact on-chain amount string — no float precision loss
	Purpose     string    `json:"purpose"`
	ChainID     int64     `json:"chain_id"`
	Nonce       string    `json:"nonce"`
	Timestamp   time.Time `json:"timestamp"`
}

// EvaluationResult is the complete output of the policy engine for one request.
// The gateway layer uses this to build the HTTP response, write the audit record,
// and (on approval) call the signing layer.
type EvaluationResult struct {
	Decision      Decision // Approved, Denied, or PendingHuman
	Tier          int      // 1 | 2 | 3 — which tier handled this decision
	DenialCode    string   // set when Decision == Denied
	DenialReason  string   // human-readable explanation — logged internally, not sent to caller on anomaly
	RiskScore     float64  // behavioral baseline score at decision time (0.0–1.0)
	AutoApproved  bool     // true if Tier 1 (amount below AutoApproveBelowUSD, baseline warm)
	PolicyVersion string   // exact version active at evaluation time
	PolicyHash    string   // keccak256 of policy.yaml at evaluation time
	FlaggedReview bool     // true if risk score exceeded review threshold but not block threshold

	// NonceExpiresAt is the expiry time the gateway must pass to WriteDecision
	// so nonce recording and decision recording happen in one atomic transaction.
	// Zero if RequireNonce is false or the request was denied before nonce recording.
	NonceExpiresAt time.Time
}

// Decision is the three possible outcomes of a policy evaluation.
type Decision string

const (
	DecisionApproved     Decision = "approved"
	DecisionDenied       Decision = "denied"
	DecisionPendingHuman Decision = "pending_human"
)

// Denial codes — used in API responses and the audit log.
// These are stable string constants. Do not rename them — the audit log
// and any downstream tooling depends on these exact strings.
const (
	CodeRequestExpired          = "REQUEST_EXPIRED"
	CodeNonceReplay             = "NONCE_REPLAY"
	CodeAgentUnknown            = "AGENT_UNKNOWN"
	CodeAgentDisabled           = "AGENT_DISABLED"
	CodePurposeMismatch         = "PURPOSE_MISMATCH"
	CodeDestinationBlocked      = "DESTINATION_BLOCKED"
	CodeDestinationNotAllowed   = "DESTINATION_NOT_ALLOWED"
	CodeExceedsTransactionLimit = "EXCEEDS_TRANSACTION_LIMIT"
	CodeExceedsHourlyLimit      = "EXCEEDS_HOURLY_LIMIT"
	CodeExceedsDailyLimit       = "EXCEEDS_DAILY_LIMIT"
	CodeBehavioralAnomaly       = "BEHAVIORAL_ANOMALY"
	CodeColdStartProtection     = "COLD_START_PROTECTION"
	CodeZeroAmount              = "ZERO_AMOUNT"
	CodeInternalError           = "INTERNAL_ERROR"
	CodePolicyUnavailable       = "POLICY_UNAVAILABLE"
)
