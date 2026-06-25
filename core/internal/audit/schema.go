package audit

import (
	"database/sql"
	"fmt"
)

// schema defines all tables and indexes for the Verilock audit database.
// Every statement uses CREATE IF NOT EXISTS — safe to run on every startup.
//
// TIMESTAMP CONVENTION:
//
//	All timestamps are stored as INTEGER Unix milliseconds (unixepoch * 1000).
//	This avoids SQLite's TEXT datetime comparison fragility — integers always
//	sort and compare correctly with >, <, BETWEEN. Go code uses .UnixMilli()
//	to write and time.UnixMilli() to read. No format strings. No timezone drift.
//
// SECURITY CONTRACT:
//   - The decisions table is append-only. No UPDATE or DELETE is ever issued
//     against it by application code. Enforced at the application layer.
//   - WAL mode is enabled before migrations run (see New() in audit.go).
//   - Foreign keys are enforced at the SQLite level.
const schema = `

-- ── decisions ─────────────────────────────────────────────────────────────────
-- One row per policy evaluation. Approved and denied decisions both produce a
-- full record. Rows are NEVER updated or deleted — this is the immutable audit trail.
CREATE TABLE IF NOT EXISTS decisions (
    id                  TEXT    PRIMARY KEY,
    request_id          TEXT    NOT NULL,
    agent_id            TEXT    NOT NULL,

    -- Outcome
    decision            TEXT    NOT NULL CHECK(decision IN ('approved','denied','pending_human')),
    tier                INTEGER NOT NULL DEFAULT 1 CHECK(tier IN (1,2,3)),
    denial_code         TEXT,               -- NULL if approved
    denial_reason       TEXT,               -- NULL if approved

    -- What was requested
    action              TEXT    NOT NULL,
    destination         TEXT    NOT NULL,
    amount_usd          REAL    NOT NULL,
    amount_raw          TEXT    NOT NULL,   -- exact on-chain amount as string (no float precision loss)
    purpose             TEXT    NOT NULL,
    chain_id            INTEGER NOT NULL,
    nonce               TEXT    NOT NULL,

    -- Policy that governed this decision
    policy_version      TEXT    NOT NULL,
    policy_hash         TEXT    NOT NULL,   -- SHA-256 of policy file at decision time
    risk_score          REAL    NOT NULL,   -- 0.0–1.0 behavioural baseline score

    -- Token (populated only if decision = 'approved')
    token_id            TEXT,
    token_expires_at    INTEGER,            -- Unix milliseconds; NULL if denied

    -- Human approval (populated only if tier = 3)
    human_approved_by   TEXT,              -- identifier of the human who decided
    human_decided_at    INTEGER,           -- Unix milliseconds; NULL if not tier 3

    -- Immutable record timestamp
    created_at          INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER))
);

-- ── used_nonces ───────────────────────────────────────────────────────────────
-- Replay attack prevention. A nonce here was consumed. Cleanup is storage hygiene.
CREATE TABLE IF NOT EXISTS used_nonces (
    nonce       TEXT    PRIMARY KEY,
    agent_id    TEXT    NOT NULL,
    used_at     INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)),
    expires_at  INTEGER NOT NULL            -- Unix milliseconds; row safe to delete after this
);

-- ── revoked_tokens ────────────────────────────────────────────────────────────
-- Loaded entirely into memory on startup for sub-millisecond revocation checks.
-- Persisted here so revocations survive server restarts.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id    TEXT    PRIMARY KEY,
    agent_id    TEXT    NOT NULL,
    revoked_at  INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER)),
    reason      TEXT
);

-- ── baseline_snapshots ────────────────────────────────────────────────────────
-- One row per agent per analysis window.
-- Used by the behavioural baseline engine to compute deviation scores over time.
CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id              TEXT    PRIMARY KEY,
    agent_id        TEXT    NOT NULL,
    window_start    INTEGER NOT NULL,       -- Unix milliseconds
    window_end      INTEGER NOT NULL,       -- Unix milliseconds
    tx_count        INTEGER NOT NULL,
    total_usd       REAL    NOT NULL,
    avg_usd         REAL    NOT NULL,
    destinations    TEXT    NOT NULL,       -- JSON array of unique destination addresses
    created_at      INTEGER NOT NULL DEFAULT (CAST((julianday('now') - 2440587.5) * 86400000 AS INTEGER))
);

-- ── indexes ───────────────────────────────────────────────────────────────────

-- Per-agent decision lookup (dashboard, audit queries)
CREATE INDEX IF NOT EXISTS idx_decisions_agent
    ON decisions(agent_id);

-- Chronological scan (log tailing, time-range exports)
CREATE INDEX IF NOT EXISTS idx_decisions_created
    ON decisions(created_at);

-- Composite: covers the exact WHERE clause used by SumApprovedUSD.
-- (agent_id, decision, created_at) — SQLite uses this for both filter and sort.
CREATE INDEX IF NOT EXISTS idx_decisions_spend
    ON decisions(agent_id, decision, created_at);

-- Nonce lookup in decisions table for audit trail linking
CREATE INDEX IF NOT EXISTS idx_decisions_nonce
    ON decisions(nonce);

-- Tier filtering — "how many transactions required human approval?"
CREATE INDEX IF NOT EXISTS idx_decisions_tier
    ON decisions(tier, created_at);

-- Nonce expiry — used by the cleanup goroutine
CREATE INDEX IF NOT EXISTS idx_nonces_expires
    ON used_nonces(expires_at);

-- Baseline agent + window lookup
CREATE INDEX IF NOT EXISTS idx_baseline_agent
    ON baseline_snapshots(agent_id, window_start);
`

// runMigrations applies the schema to db.
// Idempotent — safe to call on every startup.
// Must be called before any other database operation.
func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("audit: schema migration failed: %w", err)
	}
	return nil
}
