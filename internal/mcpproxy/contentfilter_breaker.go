// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"errors"
	"log/slog"
	"sync"
	"time"
)

// Circuit breaker port — parity reference is
// panacea-agent/services/aigw-content-filter/app/reliability.py (CircuitBreaker).
//
// Semantics and state transitions are verbatim — any divergence changes a
// load-bearing invariant documented in HANDOFF_GO_PORT_REFERENCE §4.11.

// CircuitState is the breaker state. Values must agree with the Python
// `CircuitState` IntEnum (0=CLOSED, 1=HALF_OPEN, 2=OPEN) because the
// numeric value is exported as the `mcp_filter_circuit_state` gauge and
// dashboards already key on those integers.
type CircuitState int32

const (
	// CircuitClosed — calls pass through; successes reset the failure counter.
	CircuitClosed CircuitState = 0
	// CircuitHalfOpen — a single probe is allowed after the reset timeout.
	CircuitHalfOpen CircuitState = 1
	// CircuitOpen — calls are short-circuited until the cooldown elapses.
	CircuitOpen CircuitState = 2
)

// String returns the lowercase snake_case name emitted as the `to=` label
// on `mcp_filter_circuit_transitions_total`.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitHalfOpen:
		return "half_open"
	case CircuitOpen:
		return "open"
	default:
		return "unknown"
	}
}

// ErrCircuitOpen is returned when the breaker is OPEN and the caller wants
// to escalate instead of receiving a silent `Allow() == false`.
//
// Errors.Is-friendly: callers that bind fail-open / fail-closed semantics
// on breaker rejection should compare with `errors.Is(err, ErrCircuitOpen)`.
var ErrCircuitOpen = errors.New("mcpproxy: circuit breaker open")

// CircuitBreakerConfig tunables — see Python reliability.py §CircuitBreakerConfig.
//
// All defaults match the Python side exactly:
//
//   - FailureThreshold: 10 (consecutive failures required to trip)
//   - ResetTimeout:     30s (initial cooldown before a probe is allowed)
//   - HalfOpenMaxCalls: 1  (only one probe at a time)
//
// L11 adds exponential backoff on repeated half-open failures:
//
//   - BackoffMultiplier: multiplier applied to the cooldown each time
//     a half-open probe fails (i.e. the breaker re-opens from
//     half-open without an intervening success). Default 2.0.
//   - MaxResetTimeout:   absolute ceiling for the cooldown, regardless
//     of how many consecutive re-opens accumulate. Defaults to 10 *
//     ResetTimeout (e.g. 5 min when ResetTimeout is 30s) so a
//     deeply-broken backend doesn't flap every 30s forever.
//
// The first trip always uses ResetTimeout verbatim. Each subsequent
// trip from half-open multiplies the cooldown by BackoffMultiplier,
// capped at MaxResetTimeout. A successful RecordSuccess in half-open
// resets the multiplier back to 1 so a recovered backend sees the
// original snappy cooldown again if it degrades in the future.
//
// Zero values are treated as "use the default"; every production call site
// specifies these explicitly via ConfigMap.
type CircuitBreakerConfig struct {
	FailureThreshold  int
	ResetTimeout      time.Duration
	HalfOpenMaxCalls  int
	BackoffMultiplier float64
	MaxResetTimeout   time.Duration
}

func (c CircuitBreakerConfig) withDefaults() CircuitBreakerConfig {
	if c.FailureThreshold <= 0 {
		c.FailureThreshold = 10
	}
	if c.ResetTimeout <= 0 {
		c.ResetTimeout = 30 * time.Second
	}
	if c.HalfOpenMaxCalls <= 0 {
		c.HalfOpenMaxCalls = 1
	}
	if c.BackoffMultiplier < 1 {
		// A multiplier < 1 would DECREASE cooldown on failure,
		// which is pathological. Clamp up to a safe default.
		c.BackoffMultiplier = 2.0
	}
	if c.MaxResetTimeout <= 0 {
		c.MaxResetTimeout = 10 * c.ResetTimeout
	}
	if c.MaxResetTimeout < c.ResetTimeout {
		// A misconfigured cap less than the base would clamp the
		// first cooldown to something shorter than configured.
		// Prefer the explicit ResetTimeout over a bogus cap.
		c.MaxResetTimeout = c.ResetTimeout
	}
	return c
}

// breakerClock is the injection seam for deterministic tests. Production
// uses [time.Now]; tests pass a controllable clock so state-machine timing
// can be exercised without wall-time sleeps.
type breakerClock func() time.Time

// BreakerObserver receives notifications on state transitions. It maps
// one-for-one to the Python `metrics.circuit_state` gauge and the
// `metrics.circuit_transitions_total` counter.
//
// Implementations MUST be cheap and non-blocking — they run under the
// breaker lock — and MUST NOT panic. Both methods receive the breaker's
// human-readable `name` (e.g. `"pii"`) so a single observer can service
// many breakers.
//
// A nil observer is treated as a no-op (production registers a real one in
// PR C; PR A exercise paths keep this interface minimal).
type BreakerObserver interface {
	OnState(name string, state CircuitState)
	OnTransition(name string, from, to CircuitState)
}

type nopBreakerObserver struct{}

func (nopBreakerObserver) OnState(string, CircuitState)                    {}
func (nopBreakerObserver) OnTransition(string, CircuitState, CircuitState) {}

// CircuitBreaker is a three-state breaker (CLOSED → OPEN → HALF_OPEN →
// CLOSED) safe for concurrent use from many goroutines.
//
// Usage:
//
//	br := NewCircuitBreaker("pii", CircuitBreakerConfig{...})
//	if !br.Allow() {
//	    return nil, ErrCircuitOpen
//	}
//	out, err := callDownstream(ctx)
//	if err != nil {
//	    br.RecordFailure()
//	    return nil, err
//	}
//	br.RecordSuccess()
//	return out, nil
//
// Context cancellation handling is caller-side: per §4.11 the port treats
// `context.Canceled` / `context.DeadlineExceeded` as neutral (no call to
// RecordFailure), so caller cancellation does not trip the breaker.
type CircuitBreaker struct {
	name  string
	cfg   CircuitBreakerConfig
	clock breakerClock
	log   *slog.Logger
	obs   BreakerObserver

	mu               sync.Mutex
	state            CircuitState
	failures         int
	openedAt         time.Time
	halfOpenInFlight int

	// currentCooldown is the cooldown that applies to the NEXT
	// half-open probe admission. It starts at cfg.ResetTimeout and
	// grows by cfg.BackoffMultiplier (capped at cfg.MaxResetTimeout)
	// on every half-open → open transition. RecordSuccess in
	// half-open resets it back to cfg.ResetTimeout so a recovered
	// backend gets snappy cooldowns again.
	currentCooldown time.Duration
}

// NewCircuitBreaker constructs a breaker with production defaults and a
// [time.Now] clock. Tests should use [NewCircuitBreakerWithClock].
//
// `name` becomes the `name=` label on metrics. `log` may be nil; a
// [slog.Default] logger is substituted.
func NewCircuitBreaker(name string, cfg CircuitBreakerConfig, log *slog.Logger, obs BreakerObserver) *CircuitBreaker {
	return newBreaker(name, cfg, time.Now, log, obs)
}

// NewCircuitBreakerWithClock is the test-only constructor that accepts a
// deterministic clock.
func NewCircuitBreakerWithClock(name string, cfg CircuitBreakerConfig, clock func() time.Time, log *slog.Logger, obs BreakerObserver) *CircuitBreaker {
	return newBreaker(name, cfg, clock, log, obs)
}

func newBreaker(name string, cfg CircuitBreakerConfig, clock breakerClock, log *slog.Logger, obs BreakerObserver) *CircuitBreaker {
	if clock == nil {
		clock = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	if obs == nil {
		obs = nopBreakerObserver{}
	}
	defaulted := cfg.withDefaults()
	br := &CircuitBreaker{
		name:            name,
		cfg:             defaulted,
		clock:           clock,
		log:             log,
		obs:             obs,
		state:           CircuitClosed,
		currentCooldown: defaulted.ResetTimeout,
	}
	br.obs.OnState(br.name, CircuitClosed)
	return br
}

// Name returns the breaker's identifier.
func (b *CircuitBreaker) Name() string { return b.name }

// State returns the current breaker state. Useful for tests and gauge
// snapshots. In hot-path code prefer [CircuitBreaker.Allow] which performs
// the state read and advance under a single lock.
func (b *CircuitBreaker) State() CircuitState {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.state
}

// Allow returns true if a call may proceed, advancing the state machine
// atomically. This is the ONLY admission path; do not read [State] and
// branch on it — that would race with [RecordSuccess] / [RecordFailure].
func (b *CircuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock()

	switch b.state {
	case CircuitOpen:
		// Allow a probe only after the CURRENT cooldown has
		// elapsed. currentCooldown is grown by BackoffMultiplier
		// on every consecutive re-open from half-open (L11 §
		// exponential backoff), so a persistently failing
		// backend stops flapping every ResetTimeout.
		if now.Sub(b.openedAt) >= b.currentCooldown {
			b.transitionLocked(CircuitHalfOpen)
			// Python resets inflight to 1 (not += 1); keep parity.
			b.halfOpenInFlight = 1
			return true
		}
		return false

	case CircuitHalfOpen:
		if b.halfOpenInFlight >= b.cfg.HalfOpenMaxCalls {
			return false
		}
		b.halfOpenInFlight++
		return true

	default: // CircuitClosed
		return true
	}
}

// RecordSuccess tells the breaker that the last call completed without a
// retriable error. Mirrors Python reliability.py:record_success.
//
// L11 extension: a success in half-open both closes the breaker AND
// resets the currentCooldown back to cfg.ResetTimeout so the next
// degradation cycle starts from the original snappy cooldown.
func (b *CircuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == CircuitHalfOpen {
		if b.halfOpenInFlight > 0 {
			b.halfOpenInFlight--
		}
		b.failures = 0
		// Recovery path: restore the base cooldown so a future
		// degradation doesn't inherit a stale large backoff.
		b.currentCooldown = b.cfg.ResetTimeout
		b.transitionLocked(CircuitClosed)
		return
	}
	b.failures = 0
}

// RecordFailure tells the breaker that the last call failed in a way that
// indicates downstream trouble (timeout, 5xx, connection reset, etc.).
// Callers MUST NOT record context cancellation as a failure — see §4.11.
//
// L11 extension: a failure during half-open grows currentCooldown by
// cfg.BackoffMultiplier (capped at cfg.MaxResetTimeout) before
// re-opening the breaker. A failure in CLOSED that trips the breaker
// uses the existing currentCooldown (which is the base ResetTimeout
// on the first trip, or whatever value is carried over from a prior
// open→half-open→closed cycle with RecordFailure in closed).
func (b *CircuitBreaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.state == CircuitHalfOpen {
		if b.halfOpenInFlight > 0 {
			b.halfOpenInFlight--
		}
		b.failures = b.cfg.FailureThreshold
		b.openedAt = b.clock()
		b.growCooldownLocked()
		b.transitionLocked(CircuitOpen)
		return
	}

	b.failures++
	if b.failures >= b.cfg.FailureThreshold {
		b.openedAt = b.clock()
		// First trip from CLOSED uses the current cooldown as-is
		// (which is the base ResetTimeout for a freshly-constructed
		// breaker, or the last post-backoff value if this is the
		// second trip without an intervening success).
		b.transitionLocked(CircuitOpen)
	}
}

// growCooldownLocked multiplies currentCooldown by cfg.BackoffMultiplier,
// capped at cfg.MaxResetTimeout. Caller MUST hold b.mu. Used only on
// the half-open → open transition; the CLOSED → OPEN transition
// reuses whatever cooldown is currently in place.
func (b *CircuitBreaker) growCooldownLocked() {
	scaled := time.Duration(float64(b.currentCooldown) * b.cfg.BackoffMultiplier)
	if scaled > b.cfg.MaxResetTimeout {
		scaled = b.cfg.MaxResetTimeout
	}
	if scaled < b.cfg.ResetTimeout {
		// Guard against underflow from a pathological multiplier.
		scaled = b.cfg.ResetTimeout
	}
	b.currentCooldown = scaled
}

// CurrentCooldown returns the cooldown that would apply if the breaker
// re-opened right now. Exposed for tests and for dashboard tooling
// that wants to surface the runtime backoff schedule.
func (b *CircuitBreaker) CurrentCooldown() time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.currentCooldown
}

// transitionLocked changes state and notifies the observer. Callers MUST
// hold b.mu.
func (b *CircuitBreaker) transitionLocked(to CircuitState) {
	if b.state == to {
		return
	}
	from := b.state
	b.log.Warn("mcpproxy: circuit state transition",
		slog.String("circuit", b.name),
		slog.String("from", from.String()),
		slog.String("to", to.String()),
		slog.Int("failures", b.failures),
	)
	b.state = to
	b.obs.OnState(b.name, to)
	b.obs.OnTransition(b.name, from, to)
}
