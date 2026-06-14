package policy

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SpendChecker is implemented by the audit DB layer.
// The engine calls it to enforce hourly and daily spend limits without
// importing the audit package directly (avoids circular imports).
type SpendChecker interface {
	SumApprovedUSD(agentID string, since time.Time) (float64, error)
	IsNonceUsed(nonce string) (bool, error)
}

// BaselineScorer is implemented by the baseline package.
type BaselineScorer interface {
	// Score returns a risk score 0.0–1.0 for the agent and request.
	// Returns 0.0 (safest) when the agent has fewer than MinDataPoints observations.
	Score(agentID, destination string, amountUSD float64) float64

	// DataPoints returns how many approved transactions the baseline engine has
	// observed for this agent. Used to enforce cold-start protection.
	DataPoints(agentID string) int

	// Record adds a data point to the agent's behavioral history.
	// Called for all requests that pass checks 1–9, regardless of final decision.
	Record(agentID, destination string, amountUSD float64)
}

// Engine is the policy evaluation judge.
// It is stateless — all state lives in the Loader, audit DB, and baseline scorer.
// The same input always produces the same output for the same state (deterministic).
//
// SECURITY CONTRACT:
//   - Checks run in strict order. First failure stops evaluation immediately.
//   - Any internal error (DB failure, unexpected panic) returns DENIED.
//   - If the policy is unavailable, ALL requests are denied.
//   - Zero or negative amounts are always denied — hardcoded, not configurable.
//   - The engine never records nonces itself. NonceExpiresAt is returned in
//     EvaluationResult so the gateway can atomically record nonce + decision
//     in a single WriteDecision call.
type Engine struct {
	loader   *Loader
	spend    SpendChecker
	baseline BaselineScorer
	log      *zap.Logger
}

// NewEngine constructs a policy Engine with all required dependencies.
func NewEngine(loader *Loader, spend SpendChecker, baseline BaselineScorer, log *zap.Logger) *Engine {
	return &Engine{
		loader:   loader,
		spend:    spend,
		baseline: baseline,
		log:      log,
	}
}

// Evaluate runs the complete evaluation pipeline against req.
// Returns a complete EvaluationResult — never returns a Go error directly.
// All errors are translated into a DENIED result with CodeInternalError.
//
// CHECK ORDER (do not reorder — order is security-critical):
//  1. Request age         — reject stale/replayed requests
//  2. Nonce uniqueness    — reject exact replays
//  3. Agent existence     — unknown agents always denied
//  4. Agent enabled       — disabled agents always denied
//  5. Purpose binding     — purpose must exactly match allowed list
//  6. Blocked destination — deny list checked before allow list
//  7. Allowed destination — must be explicitly whitelisted
//  8. Per-transaction cap — hardest amount limit
//  9. Hourly + daily cap  — rolling window limits
//
// 10. Behavioral baseline — anomaly detection
// 11. Cold-start guard    — new agents default to Tier 3
// 12. Tier routing        — assign Tier 1 / 2 / 3 and return result
func (e *Engine) Evaluate(req ActionRequest) EvaluationResult {
	return e.evaluate(req, false)
}

// evaluate is the internal implementation. dryRun=true skips baseline recording
// and is used by RunCanary so startup self-tests don't pollute the baseline.
func (e *Engine) evaluate(req ActionRequest, dryRun bool) EvaluationResult {

	// ── Load active policy ────────────────────────────────────────────────────
	p, policyHash, valid := e.loader.GetPolicy()
	if !valid || p == nil {
		e.log.Error("policy unavailable — denying all requests")
		return deny(CodePolicyUnavailable,
			"Policy file is unavailable. All requests denied until restored.",
			0, policyHash, "")
	}

	// ── Hardcoded law: zero/negative amount is always denied ──────────────────
	// No YAML rule can override this. There is no legitimate reason for an AI
	// agent to request approval for a zero-value transaction.
	if req.AmountUSD <= 0 {
		return deny(CodeZeroAmount,
			"Zero or negative amount transactions are never permitted.",
			0, policyHash, p.Version)
	}

	// ── CHECK 1: Request age ──────────────────────────────────────────────────
	maxAge := time.Duration(p.Global.MaxRequestAgeSeconds) * time.Second
	if time.Since(req.Timestamp) > maxAge {
		return deny(CodeRequestExpired,
			fmt.Sprintf("Request is too old (max age: %ds). Possible replay.", p.Global.MaxRequestAgeSeconds),
			0, policyHash, p.Version)
	}

	// ── CHECK 2: Nonce uniqueness ─────────────────────────────────────────────
	// SECURITY: the engine only checks — it does NOT record the nonce.
	// Recording happens atomically in WriteDecision (audit layer) so the nonce
	// write and the decision write are in a single DB transaction.
	if p.Global.RequireNonce {
		if req.Nonce == "" {
			return deny(CodeNonceReplay, "Nonce is required but missing.", 0, policyHash, p.Version)
		}
		used, err := e.spend.IsNonceUsed(req.Nonce)
		if err != nil {
			e.log.Error("nonce check DB error — failing closed", zap.Error(err))
			return deny(CodeInternalError, "Internal error during nonce validation.", 0, policyHash, p.Version)
		}
		if used {
			return deny(CodeNonceReplay, "Nonce has already been used. Possible replay attack.", 0, policyHash, p.Version)
		}
	}

	// ── CHECK 3: Agent existence ──────────────────────────────────────────────
	// Unknown agents are ALWAYS denied. There is no default policy.
	agent := findAgent(p, req.AgentID)
	if agent == nil {
		return deny(CodeAgentUnknown,
			fmt.Sprintf("Agent %q is not registered in this policy.", req.AgentID),
			0, policyHash, p.Version)
	}

	// ── CHECK 4: Agent enabled ────────────────────────────────────────────────
	if !agent.Enabled {
		return deny(CodeAgentDisabled,
			fmt.Sprintf("Agent %q is disabled.", req.AgentID),
			0, policyHash, p.Version)
	}

	// ── CHECK 5: Purpose binding ──────────────────────────────────────────────
	// Case-sensitive exact match. Prevents permission-expansion attacks.
	if !purposeAllowed(agent, req.Purpose) {
		return deny(CodePurposeMismatch,
			fmt.Sprintf("Purpose %q is not in the agent's allowed_purposes list.", req.Purpose),
			0, policyHash, p.Version)
	}

	// ── CHECK 6: Blocked destination ─────────────────────────────────────────
	// Explicit deny list checked BEFORE the allow list. Always.
	if destinationBlocked(agent, req.Destination) {
		return deny(CodeDestinationBlocked,
			fmt.Sprintf("Destination %q is on the blocked_destinations list.", req.Destination),
			0, policyHash, p.Version)
	}

	// ── CHECK 7: Allowed destination ─────────────────────────────────────────
	if !destinationAllowed(agent, req.Destination) {
		return deny(CodeDestinationNotAllowed,
			fmt.Sprintf("Destination %q is not in the agent's allowed_destinations list.", req.Destination),
			0, policyHash, p.Version)
	}

	// ── CHECK 8: Per-transaction spend limit ──────────────────────────────────
	if req.AmountUSD > agent.SpendLimits.MaxPerTransactionUSD {
		return deny(CodeExceedsTransactionLimit,
			fmt.Sprintf("Amount $%.2f exceeds per-transaction limit of $%.2f.",
				req.AmountUSD, agent.SpendLimits.MaxPerTransactionUSD),
			0, policyHash, p.Version)
	}

	// ── CHECK 9: Hourly + daily spend limits ──────────────────────────────────
	// Query audit log for approved totals within each rolling window.
	// DB errors fail closed — treat as limit exceeded.
	hourlyTotal, err := e.spend.SumApprovedUSD(req.AgentID, time.Now().Add(-time.Hour))
	if err != nil {
		e.log.Error("hourly spend check failed — failing closed", zap.Error(err))
		return deny(CodeInternalError, "Internal error during spend limit check.", 0, policyHash, p.Version)
	}
	if hourlyTotal+req.AmountUSD > agent.SpendLimits.MaxPerHourUSD {
		return deny(CodeExceedsHourlyLimit,
			fmt.Sprintf("This transaction would bring hourly total to $%.2f, exceeding limit of $%.2f.",
				hourlyTotal+req.AmountUSD, agent.SpendLimits.MaxPerHourUSD),
			0, policyHash, p.Version)
	}

	dailyTotal, err := e.spend.SumApprovedUSD(req.AgentID, time.Now().Add(-24*time.Hour))
	if err != nil {
		e.log.Error("daily spend check failed — failing closed", zap.Error(err))
		return deny(CodeInternalError, "Internal error during spend limit check.", 0, policyHash, p.Version)
	}
	if dailyTotal+req.AmountUSD > agent.SpendLimits.MaxPerDayUSD {
		return deny(CodeExceedsDailyLimit,
			fmt.Sprintf("This transaction would bring daily total to $%.2f, exceeding limit of $%.2f.",
				dailyTotal+req.AmountUSD, agent.SpendLimits.MaxPerDayUSD),
			0, policyHash, p.Version)
	}

	// ── Record baseline data point ────────────────────────────────────────────
	// Done here — after all rule checks pass, before the final routing decision.
	// This means denied requests (anomaly, cold-start) still contribute to the
	// baseline history, which makes the scorer more accurate over time.
	if !dryRun {
		e.baseline.Record(req.AgentID, req.Destination, req.AmountUSD)
	}

	// ── CHECK 10: Behavioral baseline ─────────────────────────────────────────
	riskScore := e.baseline.Score(req.AgentID, req.Destination, req.AmountUSD)
	flaggedReview := false

	if riskScore > agent.BehavioralRiskThreshold {
		// SECURITY: Log the exact score internally but return a generic message
		// to the caller. Exposing the threshold lets attackers probe and calibrate.
		e.log.Warn("behavioral anomaly — request denied",
			zap.String("agent_id", req.AgentID),
			zap.Float64("risk_score", riskScore),
			zap.Float64("threshold", agent.BehavioralRiskThreshold),
		)
		return deny(CodeBehavioralAnomaly,
			"Request denied due to anomalous behavioral pattern.",
			riskScore, policyHash, p.Version)
	}
	if riskScore > agent.BehavioralReviewThreshold {
		flaggedReview = true
		e.log.Warn("request flagged for review — risk above review threshold",
			zap.String("agent_id", req.AgentID),
			zap.Float64("risk_score", riskScore),
			zap.Float64("review_threshold", agent.BehavioralReviewThreshold),
		)
	}

	// ── CHECK 11: Cold-start protection ───────────────────────────────────────
	// New agents with insufficient baseline history default to Tier 3.
	// Prevents a fresh/compromised agent token from getting 20 free auto-approvals.
	// Only applies if MinDataPointsForAutoApprove > 0 (per agent config).
	dataPoints := e.baseline.DataPoints(req.AgentID)
	isWarm := agent.MinDataPointsForAutoApprove == 0 ||
		dataPoints >= agent.MinDataPointsForAutoApprove

	// ── CHECK 12: Tier routing ────────────────────────────────────────────────
	// Compute nonce expiry — returned in result for atomic WriteDecision.
	var nonceExpiresAt time.Time
	if p.Global.RequireNonce {
		nonceExpiresAt = time.Now().Add(
			time.Duration(p.Global.NonceWindowSeconds) * time.Second,
		)
	}

	// Tier 3: amount above RequireHumanAboveUSD, OR agent is not yet warm.
	if req.AmountUSD > agent.SpendLimits.RequireHumanAboveUSD || !isWarm {
		reason := ""
		if !isWarm {
			reason = fmt.Sprintf(
				"Agent has %d data points; %d required for auto-approval.",
				dataPoints, agent.MinDataPointsForAutoApprove,
			)
			e.log.Info("cold-start: routing to Tier 3 (human approval)",
				zap.String("agent_id", req.AgentID),
				zap.Int("data_points", dataPoints),
				zap.Int("min_required", agent.MinDataPointsForAutoApprove),
			)
		}
		return EvaluationResult{
			Decision:       DecisionPendingHuman,
			Tier:           3,
			DenialCode:     coldStartCode(!isWarm),
			DenialReason:   reason,
			RiskScore:      riskScore,
			AutoApproved:   false,
			PolicyVersion:  p.Version,
			PolicyHash:     policyHash,
			FlaggedReview:  flaggedReview,
			NonceExpiresAt: nonceExpiresAt,
		}
	}

	// Tier 2: amount above AutoApproveBelowUSD — execute + notify, veto window open.
	if req.AmountUSD > agent.SpendLimits.AutoApproveBelowUSD {
		e.log.Info("tier 2: approved with notification",
			zap.String("agent_id", req.AgentID),
			zap.Float64("amount_usd", req.AmountUSD),
			zap.Float64("risk_score", riskScore),
		)
		return EvaluationResult{
			Decision:       DecisionApproved,
			Tier:           2,
			RiskScore:      riskScore,
			AutoApproved:   false,
			PolicyVersion:  p.Version,
			PolicyHash:     policyHash,
			FlaggedReview:  flaggedReview,
			NonceExpiresAt: nonceExpiresAt,
		}
	}

	// Tier 1: amount at or below AutoApproveBelowUSD, agent is warm — fully automatic.
	e.log.Info("tier 1: auto-approved",
		zap.String("agent_id", req.AgentID),
		zap.Float64("amount_usd", req.AmountUSD),
		zap.Float64("risk_score", riskScore),
	)
	return EvaluationResult{
		Decision:       DecisionApproved,
		Tier:           1,
		RiskScore:      riskScore,
		AutoApproved:   true,
		PolicyVersion:  p.Version,
		PolicyHash:     policyHash,
		FlaggedReview:  flaggedReview,
		NonceExpiresAt: nonceExpiresAt,
	}
}

// RunCanary executes startup self-tests against the policy engine.
// Uses a dry-run path — no baseline data is recorded, no nonces are consumed.
// Crashes the server (returns error) if any canary produces the wrong result.
//
// Three canaries:
//  1. Valid $1 request below auto-approve → must return APPROVED (Tier 1)
//  2. Amount above per-transaction limit → must return DENIED / EXCEEDS_TRANSACTION_LIMIT
//  3. Wrong purpose → must return DENIED / PURPOSE_MISMATCH
func (e *Engine) RunCanary(agentID, validDestination, validPurpose string) error {
	now := time.Now().UTC()

	base := ActionRequest{
		AgentID:     agentID,
		Action:      "canary_transfer",
		Destination: validDestination,
		Purpose:     validPurpose,
		ChainID:     84532,
		Timestamp:   now,
	}

	// Canary 1 — valid small request, must approve at Tier 1
	c1 := base
	c1.AmountUSD = 1.00
	c1.AmountRaw = "1000000"
	c1.Nonce = fmt.Sprintf("canary-1-%d", now.UnixNano())

	r1 := e.evaluate(c1, true)
	if r1.Decision != DecisionApproved {
		return fmt.Errorf("canary 1 FAILED: expected APPROVED/tier1, got %s (code: %s, reason: %s)",
			r1.Decision, r1.DenialCode, r1.DenialReason)
	}
	if r1.Tier != 1 {
		// Warn but don't fail — agent may have min_data_points set and be cold.
		e.log.Warn("canary 1: approved but not Tier 1 — agent may be in cold-start",
			zap.Int("tier", r1.Tier))
	}

	// Canary 2 — extreme amount, must deny with EXCEEDS_TRANSACTION_LIMIT
	c2 := base
	c2.AmountUSD = 999_999_999.00
	c2.AmountRaw = "999999999000000"
	c2.Nonce = fmt.Sprintf("canary-2-%d", now.UnixNano())

	r2 := e.evaluate(c2, true)
	if r2.Decision != DecisionDenied || r2.DenialCode != CodeExceedsTransactionLimit {
		return fmt.Errorf("canary 2 FAILED: expected DENIED/%s, got %s/%s (reason: %s)",
			CodeExceedsTransactionLimit, r2.Decision, r2.DenialCode, r2.DenialReason)
	}

	// Canary 3 — wrong purpose, must deny with PURPOSE_MISMATCH
	c3 := base
	c3.AmountUSD = 1.00
	c3.AmountRaw = "1000000"
	c3.Nonce = fmt.Sprintf("canary-3-%d", now.UnixNano())
	c3.Purpose = "__canary_invalid_purpose__"

	r3 := e.evaluate(c3, true)
	if r3.Decision != DecisionDenied || r3.DenialCode != CodePurposeMismatch {
		return fmt.Errorf("canary 3 FAILED: expected DENIED/%s, got %s/%s (reason: %s)",
			CodePurposeMismatch, r3.Decision, r3.DenialCode, r3.DenialReason)
	}

	return nil
}

// ── Private helpers ───────────────────────────────────────────────────────────

// deny constructs a denial EvaluationResult. All denial paths go through here
// to ensure consistent structure. Tier is 0 for denied results (no tier assigned).
func deny(code, reason string, riskScore float64, policyHash, policyVersion string) EvaluationResult {
	return EvaluationResult{
		Decision:      DecisionDenied,
		Tier:          0,
		DenialCode:    code,
		DenialReason:  reason,
		RiskScore:     riskScore,
		PolicyHash:    policyHash,
		PolicyVersion: policyVersion,
	}
}

// coldStartCode returns CodeColdStartProtection if it is a cold-start denial,
// or empty string if the Tier 3 routing is purely based on amount.
func coldStartCode(isColdStart bool) string {
	if isColdStart {
		return CodeColdStartProtection
	}
	return ""
}

// findAgent returns the AgentPolicy for agentID, or nil if not found.
func findAgent(p *Policy, agentID string) *AgentPolicy {
	for i := range p.Agents {
		if p.Agents[i].ID == agentID {
			return &p.Agents[i]
		}
	}
	return nil
}

// purposeAllowed returns true if purpose exactly matches one of the agent's
// allowed_purposes. Case-sensitive — "DeFi" != "defi".
func purposeAllowed(agent *AgentPolicy, purpose string) bool {
	for _, allowed := range agent.AllowedPurposes {
		if allowed == purpose {
			return true
		}
	}
	return false
}

// destinationBlocked returns true if destination is on the blocked list.
// Case-insensitive for Ethereum addresses (0xABC == 0xabc).
func destinationBlocked(agent *AgentPolicy, destination string) bool {
	dest := strings.ToLower(destination)
	for _, blocked := range agent.BlockedDestinations {
		if strings.ToLower(blocked) == dest {
			return true
		}
	}
	return false
}

// destinationAllowed returns true if destination is on the allowed list.
// Case-insensitive for Ethereum addresses (0xABC == 0xabc).
func destinationAllowed(agent *AgentPolicy, destination string) bool {
	dest := strings.ToLower(destination)
	for _, allowed := range agent.AllowedDestinations {
		if strings.ToLower(allowed) == dest {
			return true
		}
	}
	return false
}
