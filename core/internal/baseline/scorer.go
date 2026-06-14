package baseline

import (
	"math"
	"time"
)

// Scorer computes behavioral risk scores for agent requests.
// It implements the policy.BaselineScorer interface.
//
// Risk score formula (weights sum to exactly 1.0):
//
//	frequency_score   * 0.35  — request rate vs historical average
//	amount_score      * 0.40  — Z-score deviation from historical mean
//	destination_score * 0.15  — new destination vs known destinations
//	timing_score      * 0.10  — unusual hour of day for this agent
//
// All component scores are in [0.0, 1.0]. Final score is clamped to [0.0, 1.0].
// Higher score = more anomalous.
//
// COLD-START RESPONSIBILITY:
// The Scorer does NOT enforce a minimum data point threshold — that decision
// belongs to the policy engine, which has per-agent config for it. The scorer
// will compute a score from whatever history exists (even 1 record), and it
// is the engine's job to decide whether to trust that score.
//
// ORDERING INVARIANT:
// Score() must be called BEFORE Record() for the current request. The engine
// calls baseline.Score() first (check 10), then baseline.Record() is called
// inside evaluate() before the routing decision. This ensures the current
// transaction is not already in the history when we score it — which would
// inflate the frequency component by 1.
type Scorer struct {
	tracker *Tracker
}

// NewScorer creates a Scorer backed by the given Tracker.
func NewScorer(tracker *Tracker) *Scorer {
	return &Scorer{tracker: tracker}
}

// Score computes the risk score for a proposed transaction.
// Returns 0.0 when the agent has no history (not enough data to score).
// Never returns a value outside [0.0, 1.0].
//
// MUST be called before Record() for the same request — see ordering invariant above.
func (s *Scorer) Score(agentID, destination string, amountUSD float64) float64 {
	history := s.tracker.Snapshot(agentID)

	// No history at all — return 0.0.
	// The engine is responsible for deciding whether this means cold-start Tier 3.
	if len(history) == 0 {
		return 0.0
	}

	// ── Component 1: Frequency score (weight 0.35) ────────────────────────────
	// Measures request rate vs the agent's historical average.
	// Snapshot is taken BEFORE the current request is recorded, so currentRPH
	// counts only prior requests in the last hour — no double-counting.
	// A spike to 3× the historical average scores 1.0.
	avgRPH := avgRequestsPerHour(history)
	currentRPH := requestsPerHour(history)
	frequencyScore := 0.0
	if avgRPH > 0 {
		frequencyScore = math.Min(1.0, currentRPH/(avgRPH*3.0))
	}

	// ── Component 2: Amount score (weight 0.40) ───────────────────────────────
	// Z-score normalization vs historical mean and standard deviation.
	// Below 2 std devs from mean → 0.0. Above 4 std devs → 1.0.
	mean, std := amountStats(history)
	amountScore := 0.0
	if std > 0 {
		zScore := math.Abs(amountUSD-mean) / std
		amountScore = math.Min(1.0, math.Max(0.0, (zScore-2.0)/2.0))
	} else if amountUSD != mean {
		// All historical amounts identical and this differs → maximum anomaly.
		amountScore = 1.0
	}

	// ── Component 3: Destination score (weight 0.15) ──────────────────────────
	// New (unseen) destination = 1.0. Known destination = 0.0.
	destinations := knownDestinations(history)
	destinationScore := 0.0
	if !destinations[destination] {
		destinationScore = 1.0
	}

	// ── Component 4: Timing score (weight 0.10) ───────────────────────────────
	// Measures how unusual the current hour is for this agent.
	// Rather than binary 0/1, we use a graduated scale based on how far the
	// current hour is from any known hour (wrapping around midnight).
	//
	// Distance 0   (current hour is known)    → 0.0
	// Distance 1–3 (adjacent hours)           → 0.0–0.5
	// Distance 6+  (opposite side of the day) → 1.0
	currentHour := time.Now().UTC().Hour()
	hours := normalHours(history)
	timingScore := 0.0
	if !hours[currentHour] {
		// Find minimum circular distance to any known hour.
		minDist := 24
		for knownHour := range hours {
			d := abs(currentHour - knownHour)
			if d > 12 {
				d = 24 - d // wrap around midnight
			}
			if d < minDist {
				minDist = d
			}
		}
		// Map distance to [0, 1]: 0 hours away → 0.0, 6+ hours away → 1.0.
		timingScore = math.Min(1.0, float64(minDist)/6.0)
	}

	// ── Weighted combination ──────────────────────────────────────────────────
	final := (frequencyScore * 0.35) +
		(amountScore * 0.40) +
		(destinationScore * 0.15) +
		(timingScore * 0.10)

	// Clamp to [0.0, 1.0] — floating-point arithmetic can drift slightly.
	return math.Min(1.0, math.Max(0.0, final))
}

// Record appends a transaction to the agent's behavioral history.
// Must be called AFTER Score() for the same request — see ordering invariant.
func (s *Scorer) Record(agentID, destination string, amountUSD float64) {
	s.tracker.Record(agentID, destination, amountUSD)
}

// DataPoints returns the number of recorded transactions for agentID.
// The engine uses this to enforce per-agent cold-start protection.
func (s *Scorer) DataPoints(agentID string) int {
	return s.tracker.DataPoints(agentID)
}

// abs returns the absolute value of an integer.
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
