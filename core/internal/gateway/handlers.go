package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"verilock/internal/agent"
	"verilock/internal/audit"
	"verilock/internal/policy"
	"verilock/internal/ratelimit"
	"verilock/internal/signing"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Deps holds every module the handlers need.
type Deps struct {
	Config        configProvider
	PolicyEngine  *policy.Engine
	Signer        *signing.Signer
	AuditDB       *audit.DB
	AgentRegistry *agent.Registry
	RateLimiter   *ratelimit.Limiter
	TTLSeconds    int
	MinTTLSeconds int // ApprovalTokenMinRemainingSeconds from config
	DryRun        bool
}

type configProvider interface {
	IsProduction() bool
	IsDryRun() bool
	GetTier2VetoWindowSeconds() int
}

// handlers owns all HTTP handler functions.
// cfg removed — all config access via deps.Config.
type handlers struct {
	deps Deps
	log  *zap.Logger
}

// ── POST /v1/action-check ─────────────────────────────────────────────────────

type actionCheckRequest struct {
	AgentID     string  `json:"agent_id"`
	Action      string  `json:"action"`
	Destination string  `json:"destination"`
	AmountUSD   float64 `json:"amount_usd"`
	AmountRaw   string  `json:"amount_raw"`
	Purpose     string  `json:"purpose"`
	ChainID     int64   `json:"chain_id"`
	Nonce       string  `json:"nonce"`
	Timestamp   string  `json:"timestamp"` // RFC3339
}

// actionCheckResponse status values:
//
//	"approved"                   Tier 1 — token ready to submit
//	"approved_with_notification" Tier 2 — token ready, notification sent, veto open
//	"pending_human"              Tier 3 — poll /v1/decision/:id
//	"denied"                     rejected
type actionCheckResponse struct {
	Status              string                 `json:"status"`
	DecisionID          string                 `json:"decision_id"`
	Tier                int                    `json:"tier,omitempty"`
	Token               *signing.ApprovalToken `json:"approval_token,omitempty"`
	Code                string                 `json:"code,omitempty"`
	Message             string                 `json:"message,omitempty"`
	VetoWindowSeconds   int                    `json:"veto_window_seconds,omitempty"`
	PollURL             string                 `json:"poll_url,omitempty"`
	PollIntervalSeconds int                    `json:"poll_interval_seconds,omitempty"`
}

func (h *handlers) actionCheck(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSON(w, r) {
		return
	}

	agentID, _, ok := authenticateRequest(w, r, h.deps)
	if !ok {
		return
	}

	var req actionCheckRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateActionRequest(req, agentID); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339 format")
		return
	}

	policyReq := policy.ActionRequest{
		AgentID:     req.AgentID,
		Action:      req.Action,
		Destination: req.Destination,
		AmountUSD:   req.AmountUSD,
		AmountRaw:   req.AmountRaw,
		Purpose:     req.Purpose,
		ChainID:     req.ChainID,
		Nonce:       req.Nonce,
		Timestamp:   ts,
	}

	// Policy engine runs all 12 checks including baseline scoring and tier routing.
	// baseline.Record() is called INSIDE the engine — do NOT call it again here.
	result := h.deps.PolicyEngine.Evaluate(policyReq)

	decisionID := uuid.New().String()

	// Build + sign token for Tier 1 and Tier 2 approvals.
	var token *signing.ApprovalToken
	if result.Decision == policy.DecisionApproved {
		if h.deps.DryRun {
			// 65-byte zero signature — valid length, cryptographically invalid.
			// The Guard will correctly reject it if someone submits it.
			token = &signing.ApprovalToken{
				TokenID:       uuid.New().String(),
				AgentID:       req.AgentID,
				Tier:          result.Tier,
				AutoApproved:  result.AutoApproved,
				Action:        req.Action,
				Destination:   req.Destination,
				AmountUSD:     req.AmountUSD,
				AmountRaw:     req.AmountRaw,
				Purpose:       req.Purpose,
				ChainID:       req.ChainID,
				Nonce:         req.Nonce,
				IssuedAt:      time.Now().UTC(),
				ExpiresAt:     time.Now().UTC().Add(time.Duration(h.deps.TTLSeconds) * time.Second),
				PolicyVersion: result.PolicyVersion,
				PolicyHash:    result.PolicyHash,
				RiskScore:     result.RiskScore,
				Signature:     "0x" + strings.Repeat("00", 65),
			}
		} else {
			token, err = h.deps.Signer.BuildApprovalToken(signing.BuildRequest{
				AgentID:             req.AgentID,
				PolicyVersion:       result.PolicyVersion,
				PolicyHash:          result.PolicyHash,
				Tier:                result.Tier,
				AutoApproved:        result.AutoApproved,
				Action:              req.Action,
				Destination:         req.Destination,
				AmountUSD:           req.AmountUSD,
				AmountRaw:           req.AmountRaw,
				Purpose:             req.Purpose,
				ChainID:             req.ChainID,
				Nonce:               req.Nonce,
				TTLSeconds:          h.deps.TTLSeconds,
				MinRemainingSeconds: h.deps.MinTTLSeconds,
				RiskScore:           result.RiskScore,
			})
			if err != nil {
				h.log.Error("failed to build approval token — denying",
					zap.String("agent_id", req.AgentID),
					zap.String("decision_id", decisionID),
					zap.Error(err),
				)
				result = policy.EvaluationResult{
					Decision:       policy.DecisionDenied,
					DenialCode:     policy.CodeInternalError,
					DenialReason:   "Internal signing error.",
					PolicyVersion:  result.PolicyVersion,
					PolicyHash:     result.PolicyHash,
					NonceExpiresAt: result.NonceExpiresAt,
				}
				token = nil
			}
		}
	}

	// WriteDecision atomically writes nonce + decision in one DB transaction.
	// SECURITY: if this fails, response MUST be denial regardless of policy result.
	auditRec := audit.DecisionRecord{
		ID:            decisionID,
		RequestID:     requestIDFromContext(r.Context()),
		AgentID:       req.AgentID,
		Decision:      string(result.Decision),
		Tier:          result.Tier,
		DenialCode:    result.DenialCode,
		DenialReason:  result.DenialReason,
		Action:        req.Action,
		Destination:   req.Destination,
		AmountUSD:     req.AmountUSD,
		AmountRaw:     req.AmountRaw,
		Purpose:       req.Purpose,
		ChainID:       req.ChainID,
		Nonce:         req.Nonce,
		PolicyVersion: result.PolicyVersion,
		PolicyHash:    result.PolicyHash,
		RiskScore:     result.RiskScore,
	}
	if token != nil {
		auditRec.TokenID = token.TokenID
		auditRec.TokenExpiresAt = token.ExpiresAt
	}

	if err := h.deps.AuditDB.WriteDecision(auditRec, result.NonceExpiresAt); err != nil {
		h.log.Error("audit write failed — converting approval to denial",
			zap.String("agent_id", req.AgentID),
			zap.String("decision_id", decisionID),
			zap.Error(err),
		)
		writeJSON(w, mustMarshal(actionCheckResponse{
			Status:     string(policy.DecisionDenied),
			DecisionID: decisionID,
			Code:       policy.CodeInternalError,
			Message:    "Decision could not be recorded.",
		}))
		return
	}

	h.log.Info("action decision",
		zap.String("agent_id", req.AgentID),
		zap.String("decision_id", decisionID),
		zap.String("decision", string(result.Decision)),
		zap.Int("tier", result.Tier),
		zap.Float64("amount_usd", req.AmountUSD),
		zap.Float64("risk_score", result.RiskScore),
	)

	writeJSON(w, mustMarshal(buildActionResponse(
		result,
		decisionID,
		token,
		h.deps.Config.GetTier2VetoWindowSeconds(), // Pass config value
	)))
}

// buildActionResponse constructs the tier-specific HTTP response body.
func buildActionResponse(
	result policy.EvaluationResult,
	decisionID string,
	token *signing.ApprovalToken,
	tier2VetoWindowSeconds int,
) actionCheckResponse {
	resp := actionCheckResponse{
		DecisionID: decisionID,
		Tier:       result.Tier,
	}

	switch result.Decision {
	case policy.DecisionApproved:
		if result.Tier == 2 {
			resp.Status = "approved_with_notification"
			resp.Token = token
			resp.VetoWindowSeconds = tier2VetoWindowSeconds // Use parameter
		} else {
			resp.Status = string(policy.DecisionApproved)
			resp.Token = token
		}
	case policy.DecisionPendingHuman:
		resp.Status = string(policy.DecisionPendingHuman)
		resp.PollURL = fmt.Sprintf("/v1/decision/%s", decisionID)
		resp.PollIntervalSeconds = 3
	case policy.DecisionDenied:
		resp.Status = string(policy.DecisionDenied)
		resp.Code = result.DenialCode
		resp.Message = safeDenialMessage(result.DenialCode)
	}

	return resp
}

// safeDenialMessage returns a caller-safe message — never exposes internal state.
func safeDenialMessage(code string) string {
	switch code {
	case policy.CodeRequestExpired:
		return "Request timestamp is too old. Please retry with a current timestamp."
	case policy.CodeNonceReplay:
		return "This request has already been processed."
	case policy.CodeAgentUnknown:
		return "Agent is not registered."
	case policy.CodeAgentDisabled:
		return "Agent is currently disabled."
	case policy.CodePurposeMismatch:
		return "Requested purpose is not permitted for this agent."
	case policy.CodeDestinationBlocked:
		return "Destination address is not permitted."
	case policy.CodeDestinationNotAllowed:
		return "Destination address is not on the allow list."
	case policy.CodeExceedsTransactionLimit:
		return "Transaction amount exceeds the per-transaction limit."
	case policy.CodeExceedsHourlyLimit:
		return "Transaction would exceed the hourly spend limit."
	case policy.CodeExceedsDailyLimit:
		return "Transaction would exceed the daily spend limit."
	case policy.CodeBehavioralAnomaly:
		return "Request was flagged as anomalous and denied."
	case policy.CodeColdStartProtection:
		return "Agent requires human approval until behavioral baseline is established."
	case policy.CodeZeroAmount:
		return "Zero or negative amount transactions are not permitted."
	case policy.CodePolicyUnavailable:
		return "Policy is temporarily unavailable. Please retry shortly."
	default:
		return "Request denied."
	}
}

// ── GET /v1/decision/:id ──────────────────────────────────────────────────────

type decisionPollResponse struct {
	DecisionID string                 `json:"decision_id"`
	Status     string                 `json:"status"`
	Token      *signing.ApprovalToken `json:"approval_token,omitempty"`
	Code       string                 `json:"code,omitempty"`
	Message    string                 `json:"message,omitempty"`
}

func (h *handlers) decisionPoll(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	agentID, _, ok := authenticateRequest(w, r, h.deps)
	if !ok {
		return
	}

	decisionID := strings.TrimPrefix(r.URL.Path, "/v1/decision/")
	if decisionID == "" {
		writeError(w, http.StatusBadRequest, "decision_id is required")
		return
	}

	rec, err := h.deps.AuditDB.GetDecision(decisionID)
	if err != nil {
		h.log.Error("decisionPoll: DB lookup failed",
			zap.String("decision_id", decisionID),
			zap.Error(err),
		)
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}
	if rec == nil {
		writeError(w, http.StatusNotFound, "decision not found")
		return
	}

	// SECURITY: only the submitting agent can poll its own decision.
	if rec.AgentID != agentID {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	resp := decisionPollResponse{
		DecisionID: decisionID,
		Status:     rec.Decision,
	}
	if rec.Decision == string(policy.DecisionDenied) {
		resp.Code = rec.DenialCode
		resp.Message = safeDenialMessage(rec.DenialCode)
	}

	writeJSON(w, mustMarshal(resp))
}

// ── GET /v1/health ────────────────────────────────────────────────────────────

type healthResponse struct {
	Status        string                 `json:"status"`
	Version       string                 `json:"version"`
	Checks        map[string]interface{} `json:"checks"`
	UptimeSeconds int64                  `json:"uptime_seconds"`
}

var serverStart = time.Now()

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	policyStatus := h.deps.PolicyEngine.Status(h.deps.DryRun)
	dbOK := h.deps.AuditDB.Ping() == nil

	overallStatus := "ok"
	if !policyStatus.PolicyValid || !dbOK {
		overallStatus = "degraded"
	}

	writeJSON(w, mustMarshal(healthResponse{
		Status:  overallStatus,
		Version: "1.0.1",
		Checks: map[string]interface{}{
			"policy_valid":         policyStatus.PolicyValid,
			"policy_version":       policyStatus.PolicyVersion,
			"policy_hash":          policyStatus.PolicyHash,
			"agent_count":          policyStatus.AgentCount,
			"last_reload_at":       policyStatus.LastReloadAt,
			"dry_run_mode":         policyStatus.DryRunMode,
			"signing_key_ok":       true,
			"audit_db_ok":          dbOK,
			"active_rate_limiters": h.deps.RateLimiter.AgentCount(),
		},
		UptimeSeconds: int64(time.Since(serverStart).Seconds()),
	}))
}

// ── POST /v1/agent/revoke ─────────────────────────────────────────────────────

type revokeRequest struct {
	TokenID string `json:"token_id"`
	Reason  string `json:"reason"`
}

func (h *handlers) revokeToken(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSON(w, r) {
		return
	}

	callerAgentID, _, ok := authenticateRequest(w, r, h.deps)
	if !ok {
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TokenID == "" {
		writeError(w, http.StatusBadRequest, "token_id is required")
		return
	}

	// Pass the authenticated caller's agentID for complete audit records.
	if err := h.deps.AgentRegistry.RevokeToken(req.TokenID, callerAgentID, req.Reason); err != nil {
		h.log.Error("revocation failed",
			zap.String("token_id", req.TokenID),
			zap.String("caller_agent_id", callerAgentID),
			zap.Error(err),
		)
		writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}

	h.log.Warn("token revoked via API",
		zap.String("token_id", req.TokenID),
		zap.String("caller_agent_id", callerAgentID),
		zap.String("reason", req.Reason),
	)

	writeJSON(w, mustMarshal(map[string]string{
		"status":   "revoked",
		"token_id": req.TokenID,
	}))
}

// ── Validation ────────────────────────────────────────────────────────────────

func validateActionRequest(req actionCheckRequest, authenticatedAgentID string) error {
	if req.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	if req.AgentID != authenticatedAgentID {
		return fmt.Errorf("agent_id in body does not match authenticated token")
	}
	if req.Action == "" {
		return fmt.Errorf("action is required")
	}
	if req.Destination == "" {
		return fmt.Errorf("destination is required")
	}
	if req.AmountUSD < 0 {
		return fmt.Errorf("amount_usd cannot be negative")
	}
	if req.AmountRaw == "" {
		return fmt.Errorf("amount_raw is required")
	}
	if req.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	if req.ChainID <= 0 {
		return fmt.Errorf("chain_id is required")
	}
	if req.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if req.Timestamp == "" {
		return fmt.Errorf("timestamp is required")
	}
	return nil
}

// ── Context helpers ───────────────────────────────────────────────────────────

func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}

// ── Response helpers ──────────────────────────────────────────────────────────

func mustMarshal(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(fmt.Sprintf("gateway: mustMarshal failed: %v", err))
	}
	return b
}
