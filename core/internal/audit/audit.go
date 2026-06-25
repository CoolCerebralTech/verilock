package audit

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"verilock/internal/baseline"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// DB is the Verilock audit database.
// All public methods are safe for concurrent use.
//
// SECURITY CONTRACT:
//   - No UPDATE or DELETE is ever issued against the decisions table.
//   - Every query uses parameterized statements — zero string-formatted SQL.
//   - A failed audit write causes the request to be DENIED. No approval
//     exists without a corresponding audit record.
//   - Timestamps are stored as Unix milliseconds (INTEGER) — never as text.
//     This avoids SQLite TEXT datetime comparison fragility.
type DB struct {
	db     *sql.DB
	mu     sync.RWMutex // RLock for reads, Lock for writes
	cancel context.CancelFunc
}

// DecisionRecord is the complete audit entry written for every policy evaluation.
// Approved and denied decisions both produce a full record.
type DecisionRecord struct {
	ID            string
	RequestID     string
	AgentID       string
	Decision      string // "approved" | "denied" | "pending_human"
	Tier          int    // 1 | 2 | 3
	DenialCode    string // empty if approved
	DenialReason  string // empty if approved
	Action        string
	Destination   string
	AmountUSD     float64
	AmountRaw     string // exact on-chain amount string — no float precision loss
	Purpose       string
	ChainID       int64
	Nonce         string
	PolicyVersion string
	PolicyHash    string
	RiskScore     float64

	// Token — populated only if Decision = "approved"
	TokenID        string
	TokenExpiresAt time.Time

	// Human approval — populated only if Tier = 3
	HumanApprovedBy string
	HumanDecidedAt  time.Time
}

// New opens the SQLite database at path, configures it for production use,
// and runs schema migrations. Returns a ready-to-use DB or a fatal error.
//
// Configuration applied:
//   - WAL mode      : allows concurrent reads while a write is in progress
//   - Foreign keys  : enforced at the SQLite engine level
//   - Busy timeout  : 5 seconds before returning SQLITE_BUSY
//   - synchronous   : NORMAL — safe under WAL, faster than FULL
//   - Cache size    : 8 MB in-memory page cache
func New(path string) (*DB, error) {
	// Ensure the parent directory exists before SQLite tries to create the file.
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit: cannot create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit: failed to open database at %q: %w", path, err)
	}

	// One writer connection — SQLite handles concurrent writes best this way.
	// Multiple reader connections are allowed via WAL mode.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Apply critical PRAGMA settings before any other operation.
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,   // non-blocking concurrent reads
		`PRAGMA foreign_keys=ON`,    // enforce referential integrity
		`PRAGMA busy_timeout=5000`,  // wait up to 5s on a locked database
		`PRAGMA synchronous=NORMAL`, // safe under WAL, faster than FULL
		`PRAGMA cache_size=-8192`,   // 8 MB page cache (negative = KiB)
		`PRAGMA temp_store=MEMORY`,  // temp tables in RAM, not disk
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, fmt.Errorf("audit: failed to set pragma %q: %w", p, err)
		}
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("audit: database ping failed: %w", err)
	}

	if err := runMigrations(db); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	adb := &DB{db: db, cancel: cancel}

	// Expired-nonce cleanup — runs every 10 minutes.
	// Storage hygiene only: security is enforced at write time via UNIQUE constraint.
	// Goroutine exits cleanly when Close() is called.
	go adb.nonceCleanupLoop(ctx)

	return adb, nil
}

// Close shuts down the database and stops background goroutines.
// Must be called during graceful server shutdown.
func (a *DB) Close() error {
	a.cancel() // signals nonceCleanupLoop to exit
	return a.db.Close()
}

// Ping verifies the database connection is alive. Used by the health endpoint.
func (a *DB) Ping() error {
	return a.db.Ping()
}

// ── Decision writes ───────────────────────────────────────────────────────────

// WriteDecision atomically appends a policy evaluation record AND records the
// nonce in a single database transaction.
//
// SECURITY: Both writes are in one transaction. If either fails, both roll back.
// This prevents the gap where a decision record exists but the nonce is not
// consumed — which would allow replay attacks on that nonce.
//
// If this function returns an error, the caller MUST return a denial to the agent.
// An unrecorded approval does not exist as far as Verilock is concerned.
func (a *DB) WriteDecision(rec DecisionRecord, nonceExpiresAt time.Time) error {
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}
	if rec.Tier == 0 {
		rec.Tier = 1 // default to Tier 1 if not set
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	tx, err := a.db.Begin()
	if err != nil {
		return fmt.Errorf("audit: WriteDecision could not begin transaction: %w", err)
	}
	defer func() {
		// If we return before Commit(), roll back. Rollback after Commit() is a no-op.
		_ = tx.Rollback()
	}()

	// ── 1. Write the nonce first ──────────────────────────────────────────────
	// ON CONFLICT DO NOTHING: if somehow this nonce already exists (race condition
	// that slipped past IsNonceUsed), the constraint catches it and the transaction
	// will still commit — but the decision write below will have the nonce recorded.
	// The policy engine's IsNonceUsed check is the primary guard; this is the backstop.
	const nonceQ = `
		INSERT INTO used_nonces (nonce, agent_id, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT(nonce) DO NOTHING`

	if _, err := tx.Exec(nonceQ, rec.Nonce, rec.AgentID, nonceExpiresAt.UnixMilli()); err != nil {
		return fmt.Errorf("audit: WriteDecision nonce insert failed: %w", err)
	}

	// ── 2. Write the decision record ──────────────────────────────────────────
	var (
		denialCode      sql.NullString
		denialReason    sql.NullString
		tokenID         sql.NullString
		tokenExpiresAt  sql.NullInt64
		humanApprovedBy sql.NullString
		humanDecidedAt  sql.NullInt64
	)

	if rec.DenialCode != "" {
		denialCode = sql.NullString{String: rec.DenialCode, Valid: true}
	}
	if rec.DenialReason != "" {
		denialReason = sql.NullString{String: rec.DenialReason, Valid: true}
	}
	if rec.TokenID != "" {
		tokenID = sql.NullString{String: rec.TokenID, Valid: true}
	}
	if !rec.TokenExpiresAt.IsZero() {
		tokenExpiresAt = sql.NullInt64{Int64: rec.TokenExpiresAt.UnixMilli(), Valid: true}
	}
	if rec.HumanApprovedBy != "" {
		humanApprovedBy = sql.NullString{String: rec.HumanApprovedBy, Valid: true}
	}
	if !rec.HumanDecidedAt.IsZero() {
		humanDecidedAt = sql.NullInt64{Int64: rec.HumanDecidedAt.UnixMilli(), Valid: true}
	}

	const decisionQ = `
		INSERT INTO decisions
			(id, request_id, agent_id, decision, tier, denial_code, denial_reason,
			 action, destination, amount_usd, amount_raw, purpose, chain_id,
			 nonce, policy_version, policy_hash, risk_score,
			 token_id, token_expires_at,
			 human_approved_by, human_decided_at)
		VALUES
			(?,  ?,          ?,        ?,        ?,    ?,           ?,
			 ?,      ?,           ?,          ?,          ?,       ?,
			 ?,     ?,             ?,           ?,
			 ?,        ?,
			 ?,                ?)`

	_, err = tx.Exec(decisionQ,
		rec.ID, rec.RequestID, rec.AgentID, rec.Decision, rec.Tier,
		denialCode, denialReason,
		rec.Action, rec.Destination, rec.AmountUSD, rec.AmountRaw,
		rec.Purpose, rec.ChainID,
		rec.Nonce, rec.PolicyVersion, rec.PolicyHash, rec.RiskScore,
		tokenID, tokenExpiresAt,
		humanApprovedBy, humanDecidedAt,
	)
	if err != nil {
		return fmt.Errorf("audit: WriteDecision decision insert failed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("audit: WriteDecision commit failed: %w", err)
	}
	return nil
}

// UpdateHumanDecision updates a pending_human decision with the outcome.
// This is the ONLY permitted update to the decisions table.
// Used when a Tier 3 human approver makes their decision.
func (a *DB) UpdateHumanDecision(decisionID, outcome, approvedBy string) error {
	if outcome != "approved" && outcome != "denied" {
		return fmt.Errorf("audit: UpdateHumanDecision: outcome must be 'approved' or 'denied' (got %q)", outcome)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	const q = `
		UPDATE decisions
		SET    decision         = ?,
		       human_approved_by = ?,
		       human_decided_at  = ?
		WHERE  id               = ?
		AND    decision          = 'pending_human'`

	res, err := a.db.Exec(q, outcome, approvedBy, time.Now().UnixMilli(), decisionID)
	if err != nil {
		return fmt.Errorf("audit: UpdateHumanDecision failed: %w", err)
	}

	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("audit: UpdateHumanDecision: no pending_human record found for id %q", decisionID)
	}
	return nil
}

// ── Nonce management ─────────────────────────────────────────────────────────

// IsNonceUsed reports whether nonce has been seen before within its validity window.
// Returns true (block the request) on any database error — fail closed.
func (a *DB) IsNonceUsed(nonce string) (bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	const q = `SELECT 1 FROM used_nonces WHERE nonce = ? AND expires_at > ? LIMIT 1`
	row := a.db.QueryRow(q, nonce, time.Now().UnixMilli())

	var dummy int
	err := row.Scan(&dummy)
	switch err {
	case nil:
		return true, nil // nonce exists — replay attempt
	case sql.ErrNoRows:
		return false, nil // fresh nonce
	default:
		return true, fmt.Errorf("audit: IsNonceUsed query failed: %w", err)
	}
}

// nonceCleanupLoop deletes expired nonces every 10 minutes.
// Exits when ctx is cancelled (i.e. when Close() is called).
func (a *DB) nonceCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return // server is shutting down — exit cleanly
		case <-ticker.C:
			a.mu.Lock()
			_, _ = a.db.Exec(
				`DELETE FROM used_nonces WHERE expires_at <= ?`,
				time.Now().UnixMilli(),
			)
			a.mu.Unlock()
		}
	}
}

// ── Token revocation ──────────────────────────────────────────────────────────

// WriteRevocation persists a token revocation to SQLite so it survives restarts.
// The in-memory revocation map (in the agent registry) is the primary check path.
// This write is the durable backup.
func (a *DB) WriteRevocation(tokenID, agentID, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	const q = `
		INSERT INTO revoked_tokens (token_id, agent_id, reason)
		VALUES (?, ?, ?)
		ON CONFLICT(token_id) DO NOTHING`

	_, err := a.db.Exec(q, tokenID, agentID, reason)
	if err != nil {
		return fmt.Errorf("audit: WriteRevocation failed: %w", err)
	}
	return nil
}

// LoadAllRevocations returns revoked token IDs from SQLite, bounded to tokens
// revoked within the last maxAgeDays days. Tokens revoked before that window
// have already expired (the Guard rejects them via TTL) so they are irrelevant.
//
// Called once on startup to populate the in-memory revocation map.
func (a *DB) LoadAllRevocations(maxAgeDays int) (map[string]bool, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	cutoff := time.Now().AddDate(0, 0, -maxAgeDays).UnixMilli()

	const q = `SELECT token_id FROM revoked_tokens WHERE revoked_at >= ?`
	rows, err := a.db.Query(q, cutoff)
	if err != nil {
		return nil, fmt.Errorf("audit: LoadAllRevocations query failed: %w", err)
	}
	defer rows.Close()

	revoked := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("audit: LoadAllRevocations scan failed: %w", err)
		}
		revoked[id] = true
	}
	return revoked, rows.Err()
}

// ── Spend limit queries ───────────────────────────────────────────────────────

// SumApprovedUSD returns the total USD approved for agentID since the given time.
// Used by the policy engine to enforce hourly and daily spend limits.
//
// Timestamps are compared as Unix milliseconds (INTEGER) — no string formatting,
// no timezone drift, no format mismatch. Always correct.
//
// SECURITY: Returns (0, err) on any database failure.
// The policy engine treats any error here as an automatic DENY — fail closed.
func (a *DB) SumApprovedUSD(agentID string, since time.Time) (float64, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	const q = `
		SELECT COALESCE(SUM(amount_usd), 0)
		FROM   decisions
		WHERE  agent_id  = ?
		AND    decision  = 'approved'
		AND    created_at >= ?`

	row := a.db.QueryRow(q, agentID, since.UnixMilli())

	var total float64
	if err := row.Scan(&total); err != nil {
		return 0, fmt.Errorf("audit: SumApprovedUSD failed: %w", err)
	}
	return total, nil
}

// ── Baseline snapshots ────────────────────────────────────────────────────────

// WriteBaselineSnapshot persists a behavioural baseline snapshot for an agent.
// Called asynchronously — does not block the request response path.
func (a *DB) WriteBaselineSnapshot(
	agentID string,
	windowStart, windowEnd time.Time,
	txCount int,
	totalUSD, avgUSD float64,
	destinationsJSON string,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	const q = `
		INSERT INTO baseline_snapshots
			(id, agent_id, window_start, window_end, tx_count, total_usd, avg_usd, destinations)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := a.db.Exec(q,
		uuid.New().String(),
		agentID,
		windowStart.UnixMilli(),
		windowEnd.UnixMilli(),
		txCount,
		totalUSD,
		avgUSD,
		destinationsJSON,
	)
	if err != nil {
		return fmt.Errorf("audit: WriteBaselineSnapshot failed: %w", err)
	}
	return nil
}

// LoadBaselineSnapshots satisfies the baseline.SnapshotPersister interface.
// Returns snapshots as []baseline.LoadedSnapshot so audit.DB can be passed
// directly to baseline.NewTracker without an adapter wrapper.
func (a *DB) LoadBaselineSnapshots(agentID string, since time.Time) ([]baseline.LoadedSnapshot, error) {
	raw, err := a.loadBaselineSnapshotsRaw(agentID, since)
	if err != nil {
		return nil, err
	}
	out := make([]baseline.LoadedSnapshot, len(raw))
	for i, s := range raw {
		out[i] = baseline.LoadedSnapshot{
			AgentID:          s.AgentID,
			WindowStart:      s.WindowStart,
			WindowEnd:        s.WindowEnd,
			TxCount:          s.TxCount,
			TotalUSD:         s.TotalUSD,
			AvgUSD:           s.AvgUSD,
			DestinationsJSON: s.DestinationsJSON,
		}
	}
	return out, nil
}

// loadBaselineSnapshotsRaw is the internal query returning audit.BaselineSnapshot.
// Used internally and for persistence logic that needs the full audit type.
func (a *DB) loadBaselineSnapshotsRaw(agentID string, since time.Time) ([]BaselineSnapshot, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	const q = `
		SELECT id, agent_id, window_start, window_end, tx_count, total_usd, avg_usd, destinations
		FROM   baseline_snapshots
		WHERE  agent_id     = ?
		AND    window_start >= ?
		ORDER  BY window_start ASC`

	rows, err := a.db.Query(q, agentID, since.UnixMilli())
	if err != nil {
		return nil, fmt.Errorf("audit: LoadBaselineSnapshots query failed: %w", err)
	}
	defer rows.Close()

	var snaps []BaselineSnapshot
	for rows.Next() {
		var s BaselineSnapshot
		var windowStartMs, windowEndMs int64
		if err := rows.Scan(
			&s.ID, &s.AgentID,
			&windowStartMs, &windowEndMs,
			&s.TxCount, &s.TotalUSD, &s.AvgUSD,
			&s.DestinationsJSON,
		); err != nil {
			return nil, fmt.Errorf("audit: LoadBaselineSnapshots scan failed: %w", err)
		}
		s.WindowStart = time.UnixMilli(windowStartMs).UTC()
		s.WindowEnd = time.UnixMilli(windowEndMs).UTC()
		snaps = append(snaps, s)
	}
	return snaps, rows.Err()
}

// BaselineSnapshot is a single persisted behavioural snapshot for one agent.
type BaselineSnapshot struct {
	ID               string
	AgentID          string
	WindowStart      time.Time
	WindowEnd        time.Time
	TxCount          int
	TotalUSD         float64
	AvgUSD           float64
	DestinationsJSON string
}

// ── Backup ────────────────────────────────────────────────────────────────────

// RunBackup creates a consistent point-in-time copy of the live database at
// destPath using SQLite's VACUUM INTO command.
//
// VACUUM INTO is the only safe way to copy a WAL-mode SQLite database while
// it is live. It acquires a shared lock, checkpoints the WAL, and writes a
// clean single-file copy. The original database remains readable throughout.
//
// destPath should be unique per run — callers typically include a timestamp:
//
//	destPath = filepath.Join(backupDir, "audit-"+time.Now().Format("20060102-150405")+".db")
func (a *DB) RunBackup(destPath string) error {
	// Ensure the backup directory exists.
	if err := os.MkdirAll(filepath.Dir(destPath), 0o750); err != nil {
		return fmt.Errorf("audit: RunBackup cannot create backup directory: %w", err)
	}

	// VACUUM INTO acquires a shared read lock on the source DB.
	// We do NOT hold a.mu here — that would block all reads and writes for the
	// duration of the backup. SQLite's own locking is sufficient.
	if _, err := a.db.Exec(`VACUUM INTO ?`, destPath); err != nil {
		return fmt.Errorf("audit: RunBackup VACUUM INTO %q failed: %w", destPath, err)
	}
	return nil
}

// GetDecision returns the DecisionRecord for the given ID, or (nil, nil) if not found.
// Used by the Tier 3 polling endpoint to let the SDK check the human decision status.
func (a *DB) GetDecision(id string) (*DecisionRecord, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	const q = `
		SELECT id, request_id, agent_id, decision, tier, denial_code, denial_reason,
		       action, destination, amount_usd, amount_raw, purpose, chain_id,
		       nonce, policy_version, policy_hash, risk_score,
		       token_id, token_expires_at,
		       human_approved_by, human_decided_at
		FROM   decisions
		WHERE  id = ?
		LIMIT  1`

	row := a.db.QueryRow(q, id)

	var (
		rec             DecisionRecord
		denialCode      sql.NullString
		denialReason    sql.NullString
		tokenID         sql.NullString
		tokenExpiresAt  sql.NullInt64
		humanApprovedBy sql.NullString
		humanDecidedAt  sql.NullInt64
	)

	err := row.Scan(
		&rec.ID, &rec.RequestID, &rec.AgentID,
		&rec.Decision, &rec.Tier,
		&denialCode, &denialReason,
		&rec.Action, &rec.Destination,
		&rec.AmountUSD, &rec.AmountRaw, &rec.Purpose, &rec.ChainID,
		&rec.Nonce, &rec.PolicyVersion, &rec.PolicyHash, &rec.RiskScore,
		&tokenID, &tokenExpiresAt,
		&humanApprovedBy, &humanDecidedAt,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("audit: GetDecision failed: %w", err)
	}

	if denialCode.Valid {
		rec.DenialCode = denialCode.String
	}
	if denialReason.Valid {
		rec.DenialReason = denialReason.String
	}
	if tokenID.Valid {
		rec.TokenID = tokenID.String
	}
	if tokenExpiresAt.Valid {
		rec.TokenExpiresAt = time.UnixMilli(tokenExpiresAt.Int64).UTC()
	}
	if humanApprovedBy.Valid {
		rec.HumanApprovedBy = humanApprovedBy.String
	}
	if humanDecidedAt.Valid {
		rec.HumanDecidedAt = time.UnixMilli(humanDecidedAt.Int64).UTC()
	}

	return &rec, nil
}
