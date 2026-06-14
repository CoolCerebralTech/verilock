package ratelimit

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Limiter manages two layers of rate limiting:
//  1. A global limiter — caps total server throughput across all agents.
//  2. Per-agent limiters — caps throughput for each individual agent.
//
// Both use the token bucket algorithm via golang.org/x/time/rate.
//
// SECURITY CONTRACT:
//   - Global limit is ALWAYS checked before per-agent. The Allow() method
//     enforces this internally — callers cannot accidentally skip global.
//   - Per-agent limiters are created lazily on first request from that agent.
//   - Stale per-agent limiters (no requests in 1 hour) are pruned by a
//     background goroutine to prevent unbounded memory growth.
//   - Close() stops the background goroutine cleanly.
//
// All operations are safe for concurrent use.
type Limiter struct {
	global *rate.Limiter

	mu     sync.RWMutex
	agents map[string]*agentLimiter

	agentRPS   rate.Limit
	agentBurst int

	cancel context.CancelFunc
}

type agentLimiter struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // UnixNano — updated atomically on every request
}

// Config carries all rate limit parameters.
type Config struct {
	GlobalRPS   int // max total requests/second across all agents
	GlobalBurst int // max burst for the global limiter
	AgentRPS    int // max requests/second per individual agent
	AgentBurst  int // max burst per individual agent
}

// New creates a Limiter from cfg and starts the background cleanup goroutine.
func New(cfg Config) *Limiter {
	ctx, cancel := context.WithCancel(context.Background())

	l := &Limiter{
		global:     rate.NewLimiter(rate.Limit(cfg.GlobalRPS), cfg.GlobalBurst),
		agents:     make(map[string]*agentLimiter),
		agentRPS:   rate.Limit(cfg.AgentRPS),
		agentBurst: cfg.AgentBurst,
		cancel:     cancel,
	}

	go l.cleanupLoop(ctx)
	return l
}

// Close stops the background cleanup goroutine. Call during graceful shutdown.
func (l *Limiter) Close() {
	l.cancel()
}

// AllowGlobal checks only the global rate limit bucket.
// Used by middleware before agent identity is known.
// Per-agent limiting must still be called separately via AllowAgent()
// once the agent is authenticated.
func (l *Limiter) AllowGlobal() bool {
	return l.global.Allow()
}

// AllowAgent checks only the per-agent rate limit bucket.
// Must be called AFTER AllowGlobal() — together they are equivalent to Allow().
func (l *Limiter) AllowAgent(agentID string) bool {
	return l.allowAgent(agentID)
}

// Allow checks both the global and per-agent rate limits for agentID.
// Returns false if either limit is exceeded — the caller must reject with HTTP 429.
//
// Global is checked first. If it fails, the per-agent limiter is NOT consumed
// (its token is preserved for when the global pressure subsides).
// This is the only entry point — callers cannot skip or reorder the checks.
func (l *Limiter) Allow(agentID string) bool {
	// Global check first — if this fails, skip per-agent entirely.
	if !l.global.Allow() {
		return false
	}

	// Per-agent check.
	return l.allowAgent(agentID)
}

// allowAgent checks (and lazily creates) the per-agent limiter.
// Double-checked locking prevents duplicate limiter creation under concurrency.
func (l *Limiter) allowAgent(agentID string) bool {
	l.mu.RLock()
	al, ok := l.agents[agentID]
	l.mu.RUnlock()

	if ok {
		al.lastSeen.Store(time.Now().UnixNano())
		return al.limiter.Allow()
	}

	// First request from this agent — create a new limiter.
	l.mu.Lock()
	// Double-check after acquiring write lock to avoid duplicate creation
	// when two goroutines race on the first request from the same agent.
	if al, ok = l.agents[agentID]; ok {
		l.mu.Unlock()
		al.lastSeen.Store(time.Now().UnixNano())
		return al.limiter.Allow()
	}
	newAL := &agentLimiter{
		limiter: rate.NewLimiter(l.agentRPS, l.agentBurst),
	}
	newAL.lastSeen.Store(time.Now().UnixNano())
	l.agents[agentID] = newAL
	l.mu.Unlock()

	return newAL.limiter.Allow()
}

// cleanupLoop removes per-agent limiters that have not been seen in 1 hour.
// Runs every 15 minutes. Exits when ctx is cancelled (i.e. when Close() is called).
func (l *Limiter) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-time.Hour).UnixNano()
			l.mu.Lock()
			for id, al := range l.agents {
				if al.lastSeen.Load() < cutoff {
					delete(l.agents, id)
				}
			}
			l.mu.Unlock()
		}
	}
}

// AgentCount returns the number of active per-agent limiters.
// Used by the health endpoint to monitor memory usage.
func (l *Limiter) AgentCount() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.agents)
}
