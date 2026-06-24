// cmd/server/main.go
// Verilock Notary — main entry point.
// Wires all modules and starts the HTTP gateway.
//
// Run:
//
//	go run ./cmd/server
//
// Prerequisites:
//
//	go run ./cmd/setup   (generates keys and .env on first run)
package main

import (
	"fmt"
	"os"
	"time"

	"verilock/internal/agent"
	"verilock/internal/audit"
	"verilock/internal/baseline"
	"verilock/internal/config"
	"verilock/internal/gateway"
	"verilock/internal/policy"
	"verilock/internal/ratelimit"
	"verilock/internal/signing"

	"go.uber.org/zap"
)

func main() {
	// ── Step 1: Load and validate all configuration ───────────────────────────
	// config.Load() reads env vars and keyfiles. Crashes with a full list of
	// every misconfiguration found — operators see all problems at once.
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg.PrintStartupSummary()

	// ── Step 2: Structured logger ─────────────────────────────────────────────
	var log *zap.Logger
	if cfg.IsProduction() {
		log, err = zap.NewProduction()
	} else {
		log, err = zap.NewDevelopment()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL: failed to init logger:", err)
		os.Exit(1)
	}
	defer log.Sync() //nolint:errcheck

	// ── Step 3: Audit database ────────────────────────────────────────────────
	// WAL mode, foreign keys, busy timeout — all configured inside audit.New().
	adb, err := audit.New(cfg.AuditDBPath)
	if err != nil {
		log.Fatal("audit database failed to open", zap.Error(err))
	}
	log.Info("audit database ready", zap.String("path", cfg.AuditDBPath))

	// ── Step 4: Signing service ───────────────────────────────────────────────
	// SECURITY: the private key is loaded here and sealed inside *signing.Signer.
	// It is never accessible outside the signing package after this point.
	// signing.Config carries the Guard contract address — required for the
	// EIP-712 domain separator to match the deployed Guard.
	signer, err := signing.New(signing.Config{
		PrivateKeyHex:        cfg.SigningKeyHex,
		GuardContractAddress: cfg.GuardContractAddress,
		DryRunMode:           cfg.IsDryRun(),
	})
	if err != nil {
		log.Fatal("signing service failed to load key", zap.Error(err))
	}
	log.Info("signing service ready",
		zap.String("public_address", signer.PublicAddress()),
		zap.String("guard_contract", cfg.GuardContractAddress),
		zap.Uint64("chain_id", cfg.ChainID),
	)

	// ── Step 5: Policy loader ─────────────────────────────────────────────────
	// Reads policy.yaml, validates it, and optionally watches for hot reload.
	// Fatal if the initial load fails — no policy means all requests denied.
	loader, err := policy.NewLoader(cfg.PolicyFilePath, cfg.PolicyHotReload, log)
	if err != nil {
		log.Fatal("policy loader failed on initial load", zap.Error(err))
	}
	log.Info("policy loaded",
		zap.String("path", cfg.PolicyFilePath),
		zap.Bool("hot_reload", cfg.PolicyHotReload),
	)

	// ── Step 6: Behavioral baseline ───────────────────────────────────────────
	// Tracker persists history to the audit DB hourly and hydrates on startup.
	// Pass nil as persister to run in-memory only (useful for testing).
	tracker := baseline.NewTracker(500, adb)
	scorer := baseline.NewScorer(tracker)

	// ── Step 7: Policy engine ─────────────────────────────────────────────────
	engine := policy.NewEngine(loader, adb, scorer, log)

	// ── Step 8: Startup canary tests ──────────────────────────────────────────
	// Three self-tests confirm the engine is wired correctly before accepting
	// real traffic. Uses the dedicated canary-agent from policy.yaml — the
	// trading bot's spend limits and baseline are never touched by tests.
	log.Info("running startup canary checks")
	if err := engine.RunCanary(
		"canary-agent",
		"0xCAFEBABE00000000000000000000000000000001",
		"canary_transfer",
	); err != nil {
		log.Fatal("startup canary FAILED — policy engine misconfigured", zap.Error(err))
	}
	log.Info("startup canary checks passed")

	// ── Step 9: Agent registry ────────────────────────────────────────────────
	// Loads all active revocations from SQLite into memory on startup.
	// maxRevocationAgeDays=30 matches the 30-day token lifetime.
	registry, err := agent.NewRegistry(adb, cfg.AgentTokenSecret, 30, log)
	if err != nil {
		log.Fatal("agent registry failed to initialize", zap.Error(err))
	}
	log.Info("agent registry ready",
		zap.Int("revoked_tokens_loaded", 0), // logged inside NewRegistry
	)

	// ── Step 10: Rate limiter ─────────────────────────────────────────────────
	limiter := ratelimit.New(ratelimit.Config{
		GlobalRPS:   cfg.GlobalRateLimitRPS,
		GlobalBurst: cfg.RateLimitBurst,
		AgentRPS:    cfg.RateLimitPerAgentRPS,
		AgentBurst:  cfg.RateLimitBurst,
	})

	// ── Step 11: Dry run warning ──────────────────────────────────────────────
	if cfg.IsDryRun() {
		log.Warn("DRY RUN MODE ACTIVE — no real signatures issued, all approved")
	}

	// ── Step 12: Issue a dev token (development only) ─────────────────────────
	// Printed to stdout only — never to the structured log (tokens must not
	// appear in log aggregators even in development).
	if !cfg.IsProduction() {
		tok, err := registry.IssueToken("trading-bot-01", 30*24*time.Hour)
		if err != nil {
			log.Warn("could not issue dev token", zap.Error(err))
		} else {
			fmt.Println()
			fmt.Println("  ─────────────────────────────────────────────────────────")
			fmt.Println("  DEV TOKEN — trading-bot-01")
			fmt.Println("  Use in the Authorization header:")
			fmt.Println()
			fmt.Println("  Bearer " + tok)
			fmt.Println()
			fmt.Println("  Expires: " + time.Now().Add(30*24*time.Hour).UTC().Format(time.RFC3339))
			fmt.Println("  ─────────────────────────────────────────────────────────")
			fmt.Println()
		}
	}

	// ── Step 13: Wire the HTTP gateway ────────────────────────────────────────
	deps := gateway.Deps{
		Config:        cfg,
		PolicyEngine:  engine,
		Signer:        signer,
		AuditDB:       adb,
		AgentRegistry: registry,
		RateLimiter:   limiter,
		TTLSeconds:    cfg.ApprovalTokenTTLSeconds,
		MinTTLSeconds: cfg.ApprovalTokenMinRemainingSeconds,
		DryRun:        cfg.IsDryRun(),
	}

	srv := gateway.NewServer(cfg, deps, log)

	// ── Step 14: Register shutdown hooks ─────────────────────────────────────
	// Called in order after HTTP is fully drained.
	// Register fastest/safest to close first, DB last.
	srv.OnShutdown(func() {
		log.Info("shutdown: stopping rate limiter")
		limiter.Close()
	})
	srv.OnShutdown(func() {
		log.Info("shutdown: stopping policy loader watcher")
		loader.Close()
	})
	srv.OnShutdown(func() {
		log.Info("shutdown: flushing baseline tracker")
		tracker.Close() // triggers final persist to audit DB
	})
	srv.OnShutdown(func() {
		log.Info("shutdown: zeroing signing key")
		signer.Close()
	})
	srv.OnShutdown(func() {
		log.Info("shutdown: zeroing agent registry secret")
		registry.Close()
	})
	srv.OnShutdown(func() {
		log.Info("shutdown: closing audit database")
		if err := adb.Close(); err != nil {
			log.Error("audit database close error", zap.Error(err))
		}
	})

	// ── Step 15: Start serving ─────────────────────────────────────────────────
	log.Info("verilock notary starting",
		zap.Int("port", cfg.ServerPort),
		zap.String("public_address", signer.PublicAddress()),
		zap.Uint64("chain_id", cfg.ChainID),
		zap.String("policy_version", func() string {
			v, _, _ := engine.LoaderStatus()
			return v
		}()),
		zap.Time("started_at", time.Now().UTC()),
	)

	if err := srv.Start(); err != nil {
		log.Fatal("server stopped with error", zap.Error(err))
	}
}
