// cmd/setup/main.go
// Verilock setup wizard — run once after cloning.
// Generates all cryptographic keys, creates required directories,
// writes keyfiles (chmod 600), and writes a complete .env.
//
// Usage:
//
//	go run ./cmd/setup
//	go run ./cmd/setup --force   (overwrite existing keys + .env)
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	gocrypto "github.com/ethereum/go-ethereum/crypto"
)

const banner = `
  ████████╗ ██████╗ ██╗     ██╗      ██████╗  █████╗ ████████╗███████╗
     ██╔══╝██╔═══██╗██║     ██║     ██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
     ██║   ██║   ██║██║     ██║     ██║  ███╗███████║   ██║   █████╗
     ██║   ██║   ██║██║     ██║     ██║   ██║██╔══██║   ██║   ██╔══╝
     ██║   ╚██████╔╝███████╗███████╗╚██████╔╝██║  ██║   ██║   ███████╗
     ╚═╝    ╚═════╝ ╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

  The financial trust layer for AI agents on Base.
  Setup wizard — generates keys, directories, and your .env file.
`

func main() {
	force := flag.Bool("force", false, "overwrite existing keys and .env")
	flag.Parse()

	fmt.Print(banner)
	fmt.Println("─────────────────────────────────────────────────────────────────────")
	fmt.Println()

	envPath := ".env"
	absEnvPath, _ := filepath.Abs(envPath)

	if _, err := os.Stat(envPath); err == nil && !*force {
		fmt.Printf("  ⚠  .env already exists at %s\n", absEnvPath)
		fmt.Println("     Run with --force to regenerate everything:")
		fmt.Println("     go run ./cmd/setup --force")
		fmt.Println()
		fmt.Println("  ⚠  WARNING: --force rotates the signing key.")
		fmt.Println("     If the Guard contract is deployed you will need to redeploy it.")
		fmt.Println()
		fmt.Println("  If you are already set up, you do not need to run this again.")
		os.Exit(0)
	}

	// ── Step 1: Create required directories ──────────────────────────────────
	fmt.Println("  Step 1 of 4 — Creating required directories...")
	for _, dir := range []string{"./data", "./data/backups", "./policies", "./logs"} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			fatalf("failed to create directory %s: %v", dir, err)
		}
	}
	fmt.Println("  ✓ Directories: ./data  ./data/backups  ./policies  ./logs")
	fmt.Println()

	// ── Step 2: Generate ECDSA secp256k1 signing key ─────────────────────────
	fmt.Println("  Step 2 of 4 — Generating ECDSA secp256k1 signing key...")
	time.Sleep(200 * time.Millisecond)

	privateKey, err := gocrypto.GenerateKey()
	if err != nil {
		fatalf("failed to generate signing key: %v", err)
	}
	privKeyHex := hex.EncodeToString(gocrypto.FromECDSA(privateKey))
	pubAddress := gocrypto.PubkeyToAddress(privateKey.PublicKey).Hex()

	// Write to keyfile — NOT to .env. chmod 600: owner read-only.
	notaryKeyPath := "./data/notary.key"
	if err := os.WriteFile(notaryKeyPath, []byte(privKeyHex), 0o600); err != nil {
		fatalf("failed to write signing keyfile: %v", err)
	}
	fmt.Printf("  ✓ Signing key  → %s (chmod 600)\n", notaryKeyPath)
	fmt.Printf("  ✓ Public address: %s\n", pubAddress)
	fmt.Println()

	// ── Step 3: Generate agent token HMAC secret ─────────────────────────────
	fmt.Println("  Step 3 of 4 — Generating agent token HMAC secret...")
	time.Sleep(200 * time.Millisecond)

	// 64 bytes → 128 hex chars. config.go validates minLen=64, maxLen=128.
	secretBytes := make([]byte, 64)
	if _, err := rand.Read(secretBytes); err != nil {
		fatalf("failed to generate agent secret: %v", err)
	}
	agentSecret := hex.EncodeToString(secretBytes)

	agentKeyPath := "./data/agent.key"
	if err := os.WriteFile(agentKeyPath, []byte(agentSecret), 0o600); err != nil {
		fatalf("failed to write agent secret keyfile: %v", err)
	}
	fmt.Printf("  ✓ Agent secret → %s (chmod 600)\n", agentKeyPath)
	fmt.Println()

	// ── Step 4: Write .env ────────────────────────────────────────────────────
	fmt.Println("  Step 4 of 4 — Writing .env configuration file...")
	time.Sleep(200 * time.Millisecond)

	if err := os.WriteFile(envPath, []byte(buildEnv()), 0o600); err != nil {
		fatalf("failed to write .env: %v", err)
	}
	fmt.Printf("  ✓ .env written → %s\n", absEnvPath)
	fmt.Println()

	// ── Summary ───────────────────────────────────────────────────────────────
	fmt.Println("─────────────────────────────────────────────────────────────────────")
	fmt.Println("  ✓ SETUP COMPLETE")
	fmt.Println()
	fmt.Println("  Files created:")
	fmt.Println("    .env              — server configuration (edit as needed)")
	fmt.Println("    data/notary.key   — ECDSA signing key   (never share or commit)")
	fmt.Println("    data/agent.key    — HMAC token secret   (never share or commit)")
	fmt.Println()
	fmt.Printf("  Notary public address: %s\n", pubAddress)
	fmt.Println()
	fmt.Println("  ⚠  Add data/ to .gitignore now:")
	fmt.Println("     echo 'data/' >> .gitignore")
	fmt.Println("     echo '.env'  >> .gitignore")
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  NEXT STEPS")
	fmt.Println()
	fmt.Println("  1. Edit .env — set your addresses:")
	fmt.Println("       CHAIN_ID=84532")
	fmt.Println("       GUARD_CONTRACT_ADDRESS=0x...")
	fmt.Println("       SAFE_ADDRESS=0x...")
	fmt.Println()
	fmt.Println("  2. Deploy the Guard (from contracts/):")
	fmt.Println("       forge script script/Deploy.s.sol \\")
	fmt.Printf("         --constructor-args %s 0xYOUR_SAFE\n", pubAddress)
	fmt.Println()
	fmt.Println("  3. Start the Notary:")
	fmt.Println("       go run ./cmd/server")
	fmt.Println()
	fmt.Println("  4. Install the SDK:")
	fmt.Println("       cd ../sdk && npm install")
	fmt.Println()
	fmt.Println("─────────────────────────────────────────────────────────────────────")
	fmt.Println()

	fmt.Print("  Open .env now to fill in contract addresses? [y/N]: ")
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	if strings.ToLower(strings.TrimSpace(answer)) == "y" {
		fmt.Println()
		fmt.Println("  Set these fields in .env:")
		fmt.Println("    CHAIN_ID=84532")
		fmt.Println("    GUARD_CONTRACT_ADDRESS=0x...")
		fmt.Println("    SAFE_ADDRESS=0x...")
		fmt.Println("    NOTIFICATION_WEBHOOK_URL=https://hooks.slack.com/...  (optional in dev)")
	}
	fmt.Println()
}

// buildEnv returns the complete .env file content.
// Keys are NOT embedded — they live in data/notary.key and data/agent.key.
func buildEnv() string {
	lines := []string{
		"# Verilock Notary — Environment Configuration",
		"# Generated by: go run ./cmd/setup",
		"# Generated at: " + time.Now().UTC().Format(time.RFC3339),
		"#",
		"# SECURITY: Never commit this file or the data/ directory to git.",
		"#            Keys live in data/notary.key and data/agent.key (chmod 600).",
		"#            Rotate: go run ./cmd/setup --force",
		"",
		"# ── SERVER ───────────────────────────────────────────────────────────",
		"SERVER_PORT=8080",
		"SERVER_READ_TIMEOUT_SECONDS=10",
		"SERVER_WRITE_TIMEOUT_SECONDS=10",
		"SERVER_MAX_REQUEST_BODY_BYTES=65536",
		"",
		"# ── SIGNING KEY — loaded from keyfile, NOT stored here ───────────────",
		"# Production: inject VERILOCK_SIGNING_KEY_HEX via secrets manager instead.",
		"VERILOCK_KEYFILE_PATH=./data/notary.key",
		"",
		"# ── AGENT TOKEN SECRET — loaded from keyfile, NOT stored here ─────────",
		"AGENT_SECRET_KEYFILE_PATH=./data/agent.key",
		"",
		"# ── POLICY ───────────────────────────────────────────────────────────",
		"POLICY_FILE_PATH=./policies/policy.yaml",
		"POLICY_HOT_RELOAD=true",
		"",
		"# ── AUDIT LOG ────────────────────────────────────────────────────────",
		"AUDIT_DB_PATH=./data/audit.db",
		"# Hourly backup destination. Leave empty in development.",
		"# Required in production (config.Load() enforces this).",
		"AUDIT_BACKUP_PATH=",
		"",
		"# ── RATE LIMITING ────────────────────────────────────────────────────",
		"RATE_LIMIT_PER_AGENT_RPS=10",
		"RATE_LIMIT_BURST=20",
		"GLOBAL_RATE_LIMIT_RPS=100",
		"",
		"# ── APPROVAL TOKEN ───────────────────────────────────────────────────",
		"APPROVAL_TOKEN_TTL_SECONDS=60",
		"# Refuse to issue a token with less than this many seconds of TTL left.",
		"# Prevents the Tier 3 race condition (human approves at second 58 of 60).",
		"APPROVAL_TOKEN_MIN_REMAINING_SECONDS=10",
		"",
		"# ── TIERED EXECUTION ─────────────────────────────────────────────────",
		"# Tier 2: executes immediately + notification sent. Veto window duration.",
		"TIER2_VETO_WINDOW_SECONDS=120",
		"# Tier 3: blocks until human approves. Auto-deny if no response by timeout.",
		"TIER3_APPROVAL_TIMEOUT_SECONDS=3600",
		"",
		"# ── NOTIFICATIONS ────────────────────────────────────────────────────",
		"# Slack/Teams/generic webhook for Tier 2 alerts and Tier 3 approval requests.",
		"# Leave empty in development. Required in production.",
		"NOTIFICATION_WEBHOOK_URL=",
		"NOTIFICATION_WEBHOOK_SECRET=",
		"# Options: slack | teams | generic",
		"NOTIFICATION_PROVIDER=slack",
		"",
		"# ── NETWORK / CHAIN ──────────────────────────────────────────────────",
		"# 84532 = Base Sepolia (testnet)  |  8453 = Base mainnet",
		"CHAIN_ID=84532",
		"# Set after deploying the Guard contract (contracts/script/Deploy.s.sol).",
		"# WARNING: changing this requires redeploying the Guard.",
		"GUARD_CONTRACT_ADDRESS=",
		"# Your Gnosis Safe address on Base.",
		"SAFE_ADDRESS=",
		"",
		"# ── ENVIRONMENT ──────────────────────────────────────────────────────",
		"ENVIRONMENT=development",
		"DRY_RUN_MODE=false",
		"",
	}
	return strings.Join(lines, "\n")
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "\n  FATAL: "+format+"\n\n", args...)
	os.Exit(1)
}
