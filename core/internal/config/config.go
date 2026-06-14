package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all validated runtime configuration for the Tollgate Notary.
// Populated once at startup via Load(). Never mutated after Load() returns.
//
// SECURITY CONTRACT:
//   - SigningKeyHex and AgentTokenSecret live in memory only.
//   - They are never written to disk, never logged, never serialized.
//   - They are loaded from a restricted keyfile (chmod 600) or from an env
//     var injected by a secrets manager — never from a plain .env file.
type Config struct {
	// ── Server ───────────────────────────────────────────────────────────────
	ServerPort                int
	ServerReadTimeoutSeconds  int
	ServerWriteTimeoutSeconds int
	ServerMaxRequestBodyBytes int64

	// ── Signing — SECURITY: never log, never serialize, never pass by value ──
	SigningKeyHex    string // secp256k1 ECDSA private key, 64 hex chars
	AgentTokenSecret string // HMAC secret for agent bearer tokens, 64+ hex chars

	// ── Policy ───────────────────────────────────────────────────────────────
	PolicyFilePath  string
	PolicyHotReload bool

	// ── Audit log ────────────────────────────────────────────────────────────
	AuditDBPath     string
	AuditBackupPath string // hourly backup destination; empty = no backup

	// ── Rate limiting ─────────────────────────────────────────────────────────
	RateLimitPerAgentRPS int
	RateLimitBurst       int
	GlobalRateLimitRPS   int

	// ── Approval token ────────────────────────────────────────────────────────
	ApprovalTokenTTLSeconds          int
	ApprovalTokenMinRemainingSeconds int // refuse to issue tokens with less than this much TTL left

	// ── Tiered execution ──────────────────────────────────────────────────────
	// System-level defaults. Per-agent overrides live in policy.yaml.
	//
	// Tier 1 — fully automatic:   amount < auto_approve_below_usd in policy
	// Tier 2 — notify only:       auto_approve_below_usd <= amount < require_approval_above_usd
	//                              executes immediately, notification sent, veto window opens
	// Tier 3 — full approval:     amount >= require_approval_above_usd OR anomaly detected
	//                              blocks until human approves; denied if timeout exceeded
	Tier2VetoWindowSeconds      int // how long a Tier 2 veto is accepted before decision is final
	Tier3ApprovalTimeoutSeconds int // how long to wait for human approval before auto-deny

	// ── Notifications ─────────────────────────────────────────────────────────
	// Used for Tier 2 alerts and Tier 3 approval requests.
	NotificationWebhookURL    string // empty = notifications disabled
	NotificationWebhookSecret string // HMAC secret to sign outbound webhook payloads
	NotificationProvider      string // "slack" | "teams" | "generic"

	// ── Network / chain ───────────────────────────────────────────────────────
	ChainID              uint64 // EVM chain ID — must match the Guard contract's deployment chain
	GuardContractAddress string // 0x-prefixed Ethereum address of the deployed TollgateGuard
	SafeAddress          string // 0x-prefixed Gnosis Safe address this Notary serves

	// ── Runtime ───────────────────────────────────────────────────────────────
	Environment string // "development" | "production"
	DryRunMode  bool   // true = always approve, no real signatures issued
}

// Load reads configuration from environment variables and optional keyfiles,
// validates every value, and returns a fully verified Config.
//
// Key loading priority (first found wins):
//  1. TOLLGATE_SIGNING_KEY_HEX env var   (set by secrets manager in production)
//  2. TOLLGATE_KEYFILE_PATH file         (written by cmd/setup, chmod 600)
//
// Same priority applies to AGENT_TOKEN_SECRET / AGENT_SECRET_KEYFILE_PATH.
//
// All validation errors are collected and reported together — the operator
// sees every problem in one crash, not one at a time.
func Load() (*Config, error) {
	// Load .env if present — not fatal if absent. In production, env vars
	// are injected directly by the OS or secrets manager.
	if err := godotenv.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "[config] no .env file found — reading from environment")
	}

	cfg := &Config{}
	var errs []string

	// ── SERVER ────────────────────────────────────────────────────────────────

	if v, err := requireInt("SERVER_PORT", 1, 65535); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerPort = v
	}

	if v, err := requireInt("SERVER_READ_TIMEOUT_SECONDS", 1, 300); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerReadTimeoutSeconds = v
	}

	if v, err := requireInt("SERVER_WRITE_TIMEOUT_SECONDS", 1, 300); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerWriteTimeoutSeconds = v
	}

	if v, err := requireInt64("SERVER_MAX_REQUEST_BODY_BYTES", 1024, 10*1024*1024); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerMaxRequestBodyBytes = v
	}

	// ── SIGNING KEY ───────────────────────────────────────────────────────────
	// SECURITY: loaded from env var OR keyfile — never from .env directly.
	// Errors report metadata only; the raw value is never echoed back.

	if signingKey, err := loadSecret(
		"TOLLGATE_SIGNING_KEY_HEX",
		"TOLLGATE_KEYFILE_PATH",
		64, 64,
	); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.SigningKeyHex = signingKey
	}

	// ── AGENT TOKEN SECRET ────────────────────────────────────────────────────
	// SECURITY: same loading strategy as the signing key.

	if agentSecret, err := loadSecret(
		"AGENT_TOKEN_SECRET",
		"AGENT_SECRET_KEYFILE_PATH",
		64, 128,
	); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.AgentTokenSecret = agentSecret
	}

	// ── POLICY ───────────────────────────────────────────────────────────────

	if v := os.Getenv("POLICY_FILE_PATH"); v == "" {
		errs = append(errs, "POLICY_FILE_PATH is required but not set")
	} else {
		cfg.PolicyFilePath = v
	}

	cfg.PolicyHotReload = parseBool("POLICY_HOT_RELOAD", true)

	// ── AUDIT LOG ─────────────────────────────────────────────────────────────

	if v := os.Getenv("AUDIT_DB_PATH"); v == "" {
		errs = append(errs, "AUDIT_DB_PATH is required but not set")
	} else {
		cfg.AuditDBPath = v
	}

	// Optional — empty means no file backup (still logs to DB).
	cfg.AuditBackupPath = os.Getenv("AUDIT_BACKUP_PATH")

	// ── RATE LIMITING ─────────────────────────────────────────────────────────

	if v, err := requireInt("RATE_LIMIT_PER_AGENT_RPS", 1, 10_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.RateLimitPerAgentRPS = v
	}

	if v, err := requireInt("RATE_LIMIT_BURST", 1, 10_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.RateLimitBurst = v
	}

	if v, err := requireInt("GLOBAL_RATE_LIMIT_RPS", 1, 100_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.GlobalRateLimitRPS = v
	}

	// ── APPROVAL TOKEN ────────────────────────────────────────────────────────

	if v, err := requireInt("APPROVAL_TOKEN_TTL_SECONDS", 10, 3600); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ApprovalTokenTTLSeconds = v
	}

	if v, err := requireInt("APPROVAL_TOKEN_MIN_REMAINING_SECONDS", 5, 60); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ApprovalTokenMinRemainingSeconds = v
	}

	// Guard: min remaining must be less than the full TTL — otherwise every
	// token would be rejected the moment it's issued.
	if cfg.ApprovalTokenMinRemainingSeconds >= cfg.ApprovalTokenTTLSeconds {
		errs = append(errs, fmt.Sprintf(
			"APPROVAL_TOKEN_MIN_REMAINING_SECONDS (%d) must be less than APPROVAL_TOKEN_TTL_SECONDS (%d)",
			cfg.ApprovalTokenMinRemainingSeconds, cfg.ApprovalTokenTTLSeconds,
		))
	}

	// ── TIERED EXECUTION ─────────────────────────────────────────────────────

	if v, err := requireInt("TIER2_VETO_WINDOW_SECONDS", 10, 86400); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.Tier2VetoWindowSeconds = v
	}

	if v, err := requireInt("TIER3_APPROVAL_TIMEOUT_SECONDS", 60, 86400); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.Tier3ApprovalTimeoutSeconds = v
	}

	// ── NOTIFICATIONS ─────────────────────────────────────────────────────────
	// Webhook is optional in development; required in production (you need
	// somewhere to send Tier 2 and Tier 3 alerts).

	cfg.NotificationWebhookURL = strings.TrimSpace(os.Getenv("NOTIFICATION_WEBHOOK_URL"))
	cfg.NotificationWebhookSecret = os.Getenv("NOTIFICATION_WEBHOOK_SECRET")

	provider := strings.ToLower(strings.TrimSpace(os.Getenv("NOTIFICATION_PROVIDER")))
	if provider == "" {
		provider = "slack"
	}
	switch provider {
	case "slack", "teams", "generic":
		cfg.NotificationProvider = provider
	default:
		errs = append(errs, fmt.Sprintf(
			"NOTIFICATION_PROVIDER must be 'slack', 'teams', or 'generic' (got %q)", provider,
		))
	}

	// ── NETWORK / CHAIN ───────────────────────────────────────────────────────

	if v, err := requireUint64("CHAIN_ID", 1, 1_000_000_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ChainID = v
	}

	if v, err := requireEthAddress("GUARD_CONTRACT_ADDRESS"); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.GuardContractAddress = v
	}

	if v, err := requireEthAddress("SAFE_ADDRESS"); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.SafeAddress = v
	}

	// ── ENVIRONMENT ───────────────────────────────────────────────────────────

	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	if env == "" {
		env = "development"
	}
	switch env {
	case "development", "production":
		cfg.Environment = env
	default:
		errs = append(errs, fmt.Sprintf(
			"ENVIRONMENT must be 'development' or 'production' (got %q)", env,
		))
	}

	// ── DRY RUN MODE ──────────────────────────────────────────────────────────
	// SECURITY: bypasses real signing. Strictly forbidden in production.

	dryRun := parseBool("DRY_RUN_MODE", false)
	if dryRun && env == "production" {
		errs = append(errs, "FATAL: DRY_RUN_MODE=true is forbidden when ENVIRONMENT=production")
	}
	cfg.DryRunMode = dryRun

	// ── PRODUCTION COMPLETENESS CHECKS ───────────────────────────────────────
	// Extra rules that only apply in production. Developers can omit these
	// for local testing; production operators must supply them.

	if env == "production" {
		if cfg.NotificationWebhookURL == "" {
			errs = append(errs, "NOTIFICATION_WEBHOOK_URL is required in production (Tier 2 and Tier 3 have nowhere to send alerts)")
		}
		if cfg.AuditBackupPath == "" {
			errs = append(errs, "AUDIT_BACKUP_PATH is required in production (single-server SQLite needs an off-site backup)")
		}
	}

	// ── COLLECT ALL ERRORS ────────────────────────────────────────────────────

	if len(errs) > 0 {
		return nil, fmt.Errorf(
			"Tollgate cannot start — %d configuration error(s):\n  ✗ %s",
			len(errs),
			strings.Join(errs, "\n  ✗ "),
		)
	}

	return cfg, nil
}

// PrintStartupSummary logs safe (non-secret) configuration to stdout on boot.
// SECURITY: signing key and agent secret are intentionally excluded.
func (c *Config) PrintStartupSummary() {
	sep := "  ──────────────────────────────────────"

	fmt.Println()
	fmt.Println("  ╷ TOLLGATE NOTARY")
	fmt.Println("  ╵ runtime config")
	fmt.Println(sep)
	fmt.Printf("  %-28s %s\n", "environment", c.Environment)
	fmt.Printf("  %-28s %d\n", "port", c.ServerPort)
	fmt.Printf("  %-28s chain %d\n", "network", c.ChainID)
	fmt.Printf("  %-28s %s\n", "guard contract", truncate(c.GuardContractAddress, 30))
	fmt.Printf("  %-28s %s\n", "safe address", truncate(c.SafeAddress, 30))
	fmt.Println(sep)
	fmt.Printf("  %-28s %s\n", "policy file", truncate(c.PolicyFilePath, 30))
	fmt.Printf("  %-28s %v\n", "hot reload", c.PolicyHotReload)
	fmt.Println(sep)
	fmt.Printf("  %-28s %ds ttl / min %ds remaining\n", "approval token",
		c.ApprovalTokenTTLSeconds, c.ApprovalTokenMinRemainingSeconds)
	fmt.Printf("  %-28s %ds veto window\n", "tier 2 notify", c.Tier2VetoWindowSeconds)
	fmt.Printf("  %-28s %ds timeout\n", "tier 3 approval", c.Tier3ApprovalTimeoutSeconds)
	if c.NotificationWebhookURL != "" {
		fmt.Printf("  %-28s %s (%s)\n", "notifications", "enabled", c.NotificationProvider)
	} else {
		fmt.Printf("  %-28s disabled (set NOTIFICATION_WEBHOOK_URL)\n", "notifications")
	}
	fmt.Println(sep)
	fmt.Printf("  %-28s %s\n", "audit db", truncate(c.AuditDBPath, 30))
	if c.AuditBackupPath != "" {
		fmt.Printf("  %-28s %s\n", "audit backup", truncate(c.AuditBackupPath, 30))
	} else {
		fmt.Printf("  %-28s disabled\n", "audit backup")
	}
	fmt.Println(sep)
	fmt.Printf("  %-28s %d req/s (burst %d)\n", "global rate cap",
		c.GlobalRateLimitRPS, c.RateLimitBurst)
	fmt.Println(sep)
	fmt.Printf("  %-28s %s\n", "signing key", "[ sealed — never logged ]")
	fmt.Printf("  %-28s %s\n", "agent secret", "[ sealed — never logged ]")
	fmt.Println(sep)

	if c.DryRunMode {
		fmt.Println()
		fmt.Println("  ⚠  DRY RUN MODE ACTIVE")
		fmt.Println("     All requests return APPROVED.")
		fmt.Println("     No real signatures are issued.")
		fmt.Println("     Never run this in production.")
		fmt.Println()
	}
}

// IsProduction returns true when running in production mode.
func (c *Config) IsProduction() bool { return c.Environment == "production" }

// IsDryRun returns true when DRY_RUN_MODE is active.
func (c *Config) IsDryRun() bool { return c.DryRunMode }

// NotificationsEnabled returns true when a webhook URL is configured.
func (c *Config) NotificationsEnabled() bool { return c.NotificationWebhookURL != "" }

// GetTier2VetoWindowSeconds returns the configured Tier 2 veto window duration.
func (c *Config) GetTier2VetoWindowSeconds() int { return c.Tier2VetoWindowSeconds }

// ── Private helpers ───────────────────────────────────────────────────────────

// loadSecret loads a sensitive hex string with this priority:
//  1. Direct env var (envKey) — used in production via secrets manager
//  2. Keyfile at path given by fileKey env var — written by cmd/setup
//
// minLen / maxLen are the required hex character counts.
// SECURITY: the raw value is never included in error messages.
func loadSecret(envKey, fileKey string, minLen, maxLen int) (string, error) {
	// Priority 1: direct env var
	if val := os.Getenv(envKey); val != "" {
		return validateHexSecret(envKey, val, minLen, maxLen)
	}

	// Priority 2: keyfile
	keyfilePath := strings.TrimSpace(os.Getenv(fileKey))
	if keyfilePath == "" {
		return "", fmt.Errorf(
			"%s is not set and %s is not set — provide one of these",
			envKey, fileKey,
		)
	}

	raw, err := os.ReadFile(keyfilePath)
	if err != nil {
		return "", fmt.Errorf(
			"cannot read keyfile for %s at %q: %v (run: go run ./cmd/setup)",
			envKey, keyfilePath, err,
		)
	}

	val := strings.TrimSpace(string(raw))
	return validateHexSecret(envKey+" (from keyfile)", val, minLen, maxLen)
}

// validateHexSecret checks length and encoding of a hex secret.
// SECURITY: never logs or echoes the value — reports length metadata only.
func validateHexSecret(label, val string, minLen, maxLen int) (string, error) {
	switch {
	case len(val) < minLen:
		return "", fmt.Errorf(
			"%s must be at least %d hex characters (got %d)",
			label, minLen, len(val),
		)
	case len(val) > maxLen:
		return "", fmt.Errorf(
			"%s must be at most %d hex characters (got %d)",
			label, maxLen, len(val),
		)
	}
	if _, err := hex.DecodeString(val); err != nil {
		return "", fmt.Errorf("%s contains invalid non-hex characters", label)
	}
	return val, nil
}

// requireInt reads key from env, validates it is an integer within [min, max].
func requireInt(key string, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, fmt.Errorf("%s is required but not set", key)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number (could not parse value)", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", key, min, max, n)
	}
	return n, nil
}

// requireInt64 is requireInt for int64 values (e.g. byte limits).
func requireInt64(key string, min, max int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, fmt.Errorf("%s is required but not set", key)
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number (could not parse value)", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", key, min, max, n)
	}
	return n, nil
}

// requireUint64 reads an unsigned integer (e.g. chain IDs, which are always positive).
func requireUint64(key string, min, max uint64) (uint64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, fmt.Errorf("%s is required but not set", key)
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a positive whole number (could not parse value)", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", key, min, max, n)
	}
	return n, nil
}

// requireEthAddress reads a 0x-prefixed 42-character Ethereum address.
// Does not perform EIP-55 checksum validation — that is the responsibility
// of the caller that uses the address.
func requireEthAddress(key string) (string, error) {
	val := strings.TrimSpace(os.Getenv(key))
	if val == "" {
		return "", fmt.Errorf("%s is required but not set", key)
	}
	if len(val) != 42 {
		return "", fmt.Errorf(
			"%s must be a 42-character 0x-prefixed Ethereum address (got %d characters)",
			key, len(val),
		)
	}
	if !strings.HasPrefix(val, "0x") && !strings.HasPrefix(val, "0X") {
		return "", fmt.Errorf("%s must start with 0x", key)
	}
	if _, err := hex.DecodeString(val[2:]); err != nil {
		return "", fmt.Errorf("%s contains invalid hex characters after 0x", key)
	}
	return val, nil
}

// parseBool reads a boolean env var with a fallback default.
// Accepts: "true","1","yes" → true | "false","0","no" → false
func parseBool(key string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return defaultVal
	}
}

// truncate shortens a string for display purposes only — never for logic.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
