// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeClock is the Go analog of the Python FakeClock — a controllable
// monotonic-like clock so state-machine tests never block on wall time.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	// Use a stable anchor so durations are readable in debug output.
	return &fakeClock{now: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// recordingObserver captures (name, state) and (name, from, to) tuples so
// tests can assert metric emissions without wiring a real Prometheus
// registry. The production observer gets wired in PR C; here we only care
// that transitions fire the expected edges.
type recordingObserver struct {
	mu          sync.Mutex
	state       map[string]CircuitState
	transitions []transitionEvent
}

type transitionEvent struct {
	Name string
	From CircuitState
	To   CircuitState
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{state: map[string]CircuitState{}}
}

func (o *recordingObserver) OnState(name string, s CircuitState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.state[name] = s
}

func (o *recordingObserver) OnTransition(name string, from, to CircuitState) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.transitions = append(o.transitions, transitionEvent{name, from, to})
}

func (o *recordingObserver) CountTransitionsTo(name string, to CircuitState) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	n := 0
	for _, ev := range o.transitions {
		if ev.Name == name && ev.To == to {
			n++
		}
	}
	return n
}

// quietLogger returns a slog logger that discards output, so tests that
// intentionally trip the breaker don't spam test output with warnings.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// --- TestCircuitBreakerStates ------------------------------------------

func TestCircuitBreaker_StartsClosed(t *testing.T) {
	br := NewCircuitBreaker("pii", CircuitBreakerConfig{}, quietLogger(), nil)
	require.Equal(t, CircuitClosed, br.State())
	require.True(t, br.Allow())
}

func TestCircuitBreaker_TripsAfterThreshold(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 3, ResetTimeout: 10 * time.Second},
		clock.Now, quietLogger(), nil,
	)
	for i := 0; i < 3; i++ {
		br.RecordFailure()
	}
	require.Equal(t, CircuitOpen, br.State())
	require.False(t, br.Allow())
}

func TestCircuitBreaker_DoesNotTripBelowThreshold(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 5},
		clock.Now, quietLogger(), nil,
	)
	for i := 0; i < 4; i++ {
		br.RecordFailure()
	}
	require.Equal(t, CircuitClosed, br.State())
	require.True(t, br.Allow())
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 3},
		clock.Now, quietLogger(), nil,
	)
	br.RecordFailure()
	br.RecordFailure()
	br.RecordSuccess()
	// Two further failures must NOT trip — counter was reset.
	br.RecordFailure()
	br.RecordFailure()
	require.Equal(t, CircuitClosed, br.State())
}

func TestCircuitBreaker_HalfOpenProbeAfterCooldown(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{
			FailureThreshold: 2,
			ResetTimeout:     5 * time.Second,
			HalfOpenMaxCalls: 1,
		},
		clock.Now, quietLogger(), nil,
	)
	br.RecordFailure()
	br.RecordFailure()
	require.Equal(t, CircuitOpen, br.State())

	clock.Advance(4 * time.Second)
	require.False(t, br.Allow(), "still within cooldown")

	clock.Advance(2 * time.Second) // total 6s > 5s reset
	require.True(t, br.Allow(), "reset timeout elapsed — probe allowed")
	require.Equal(t, CircuitHalfOpen, br.State())
}

func TestCircuitBreaker_HalfOpenSuccessClosesCircuit(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Second},
		clock.Now, quietLogger(), nil,
	)
	br.RecordFailure()
	clock.Advance(2 * time.Second)
	require.True(t, br.Allow())
	require.Equal(t, CircuitHalfOpen, br.State())

	br.RecordSuccess()
	require.Equal(t, CircuitClosed, br.State())
}

func TestCircuitBreaker_HalfOpenFailureReopens(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Second},
		clock.Now, quietLogger(), nil,
	)
	br.RecordFailure()
	clock.Advance(2 * time.Second)
	require.True(t, br.Allow())
	require.Equal(t, CircuitHalfOpen, br.State())

	br.RecordFailure()
	require.Equal(t, CircuitOpen, br.State())
}

func TestCircuitBreaker_HalfOpenRejectsConcurrentProbes(t *testing.T) {
	// With HalfOpenMaxCalls=1 only ONE probe may be in flight at a time.
	// A second concurrent Allow while the probe is outstanding must fail.
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{
			FailureThreshold: 1,
			ResetTimeout:     time.Second,
			HalfOpenMaxCalls: 1,
		},
		clock.Now, quietLogger(), nil,
	)
	br.RecordFailure()
	clock.Advance(2 * time.Second)

	first := br.Allow()
	second := br.Allow()
	require.True(t, first)
	require.False(t, second)
}

func TestCircuitBreaker_HalfOpenAllowsNextProbeAfterSuccessAndSecondTrip(t *testing.T) {
	// Regression guard: if the breaker tripped once, recovered, then
	// tripped again, the inflight counter must be back to zero before
	// the next probe is admitted. (Python reliability.py resets to 1 on
	// the allow() path, not += 1.)
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Second, HalfOpenMaxCalls: 1},
		clock.Now, quietLogger(), nil,
	)
	br.RecordFailure() // CLOSED → OPEN
	clock.Advance(2 * time.Second)
	require.True(t, br.Allow()) // OPEN → HALF_OPEN, inflight=1
	br.RecordSuccess()          // HALF_OPEN → CLOSED, inflight=0
	br.RecordFailure()          // CLOSED → OPEN again
	clock.Advance(2 * time.Second)
	require.True(t, br.Allow(), "second probe must be admitted after fresh trip")
}

// --- TestCircuitBreakerConcurrency -------------------------------------

func TestCircuitBreaker_RecordsFailureAcrossGoroutines(t *testing.T) {
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 10},
		clock.Now, quietLogger(), nil,
	)
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			br.RecordFailure()
		}()
	}
	wg.Wait()
	require.Equal(t, CircuitOpen, br.State())
}

func TestCircuitBreaker_AllowAndRecordDoNotRace(t *testing.T) {
	// Hammer the breaker from many goroutines to catch any missing
	// mutex protection under `go test -race`.
	clock := newFakeClock()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 5, ResetTimeout: time.Millisecond},
		clock.Now, quietLogger(), nil,
	)

	const goroutines = 32
	const iters = 200
	var wg sync.WaitGroup
	var allowed int64
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if br.Allow() {
					atomic.AddInt64(&allowed, 1)
					if (g+i)%3 == 0 {
						br.RecordFailure()
					} else {
						br.RecordSuccess()
					}
				}
				if i%50 == 0 {
					clock.Advance(2 * time.Millisecond)
				}
			}
		}(g)
	}
	wg.Wait()
	// No deadlock and no data race — allowed count must be >= 0 and
	// state must be one of the three valid values.
	require.GreaterOrEqual(t, atomic.LoadInt64(&allowed), int64(0))
	s := br.State()
	require.True(t, s == CircuitClosed || s == CircuitOpen || s == CircuitHalfOpen)
}

// --- TestCircuitBreakerMetrics -----------------------------------------

func TestCircuitBreaker_TransitionsEmitObserverEvents(t *testing.T) {
	clock := newFakeClock()
	obs := newRecordingObserver()
	br := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: time.Second},
		clock.Now, quietLogger(), obs,
	)

	br.RecordFailure() // CLOSED → OPEN
	clock.Advance(2 * time.Second)
	require.True(t, br.Allow()) // OPEN → HALF_OPEN
	br.RecordSuccess()          // HALF_OPEN → CLOSED

	require.Equal(t, 1, obs.CountTransitionsTo("pii", CircuitOpen))
	require.Equal(t, 1, obs.CountTransitionsTo("pii", CircuitHalfOpen))
	require.Equal(t, 1, obs.CountTransitionsTo("pii", CircuitClosed))
}

func TestCircuitBreaker_InitialOnStateFires(t *testing.T) {
	obs := newRecordingObserver()
	_ = NewCircuitBreaker("pii", CircuitBreakerConfig{}, quietLogger(), obs)

	obs.mu.Lock()
	defer obs.mu.Unlock()
	require.Equal(t, CircuitClosed, obs.state["pii"])
}

func TestCircuitBreaker_StateStringStableForMetrics(t *testing.T) {
	// Metric labels depend on these strings; any rename silently breaks
	// dashboards, so we pin them here.
	require.Equal(t, "closed", CircuitClosed.String())
	require.Equal(t, "half_open", CircuitHalfOpen.String())
	require.Equal(t, "open", CircuitOpen.String())
}

func TestCircuitBreakerConfig_Defaults(t *testing.T) {
	cfg := CircuitBreakerConfig{}.withDefaults()
	require.Equal(t, 10, cfg.FailureThreshold)
	require.Equal(t, 30*time.Second, cfg.ResetTimeout)
	require.Equal(t, 1, cfg.HalfOpenMaxCalls)
}

func TestCircuitBreakerConfig_OverridesPreserved(t *testing.T) {
	cfg := CircuitBreakerConfig{
		FailureThreshold: 42,
		ResetTimeout:     7 * time.Second,
		HalfOpenMaxCalls: 3,
	}.withDefaults()
	require.Equal(t, 42, cfg.FailureThreshold)
	require.Equal(t, 7*time.Second, cfg.ResetTimeout)
	require.Equal(t, 3, cfg.HalfOpenMaxCalls)
}
