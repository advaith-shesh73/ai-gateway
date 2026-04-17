// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestCardinalityGuard_AdmitsUpToCap proves the first N unique tuples
// are admitted verbatim, the (N+1)th and beyond are rewritten, and
// repeat submissions of already-admitted tuples stay verbatim.
func TestCardinalityGuard_AdmitsUpToCap(t *testing.T) {
	g := NewCardinalityGuard(3, nil)

	// First three distinct tuples fit.
	for i, tuple := range [][]string{
		{"r1", "b1"},
		{"r2", "b2"},
		{"r3", "b3"},
	} {
		got := g.Normalize(tuple...)
		require.Equal(t, tuple, got, "tuple %d must pass unchanged", i)
	}
	require.Equal(t, 3, g.SeenCount())
	require.Equal(t, int64(0), g.OverflowCount())

	// Repeat an existing tuple — still unchanged, no new overflow.
	got := g.Normalize("r1", "b1")
	require.Equal(t, []string{"r1", "b1"}, got)
	require.Equal(t, int64(0), g.OverflowCount())

	// Fourth distinct tuple overflows.
	got = g.Normalize("r4", "b4")
	require.Equal(t, []string{CardinalityOverflowLabel, CardinalityOverflowLabel}, got)
	require.Equal(t, int64(1), g.OverflowCount())

	// Fifth also overflows and counter climbs.
	got = g.Normalize("r5", "b5")
	require.Equal(t, []string{CardinalityOverflowLabel, CardinalityOverflowLabel}, got)
	require.Equal(t, int64(2), g.OverflowCount())
}

// TestCardinalityGuard_Reset clears admitted tuples but preserves the
// overflow counter (it's a running total for alerting).
func TestCardinalityGuard_Reset(t *testing.T) {
	g := NewCardinalityGuard(1, nil)
	_ = g.Normalize("r1", "b1")
	_ = g.Normalize("r2", "b2") // overflow
	require.Equal(t, int64(1), g.OverflowCount())
	g.Reset()
	require.Equal(t, 0, g.SeenCount())
	require.Equal(t, int64(1), g.OverflowCount(), "overflow counter preserved across reset")

	// After reset, a previously-overflowed tuple is admitted.
	got := g.Normalize("r2", "b2")
	require.Equal(t, []string{"r2", "b2"}, got)
}

// TestCardinalityGuard_ConcurrentRace pushes 200 goroutines at a
// cap-of-8 guard. Under the race detector this exposes any unguarded
// map access. Confirms:
//   - seen count never exceeds cap
//   - total distinct output tuples == cap + 1 (the cap admitted
//     tuples plus the single overflow tuple)
func TestCardinalityGuard_ConcurrentRace(t *testing.T) {
	const (
		capacity   = 8
		goroutines = 200
		perG       = 10
	)
	g := NewCardinalityGuard(capacity, nil)
	var mu sync.Mutex
	distinct := map[string]struct{}{}

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(gi int) {
			defer wg.Done()
			for j := 0; j < perG; j++ {
				got := g.Normalize("route", string(rune('a'+gi%30)))
				mu.Lock()
				distinct[got[0]+"|"+got[1]] = struct{}{}
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	require.LessOrEqual(t, g.SeenCount(), capacity, "admitted count must not exceed capacity")
	require.LessOrEqual(t, len(distinct), capacity+1,
		"emitted tuples must be bounded by capacity admitted + 1 overflow; got %d", len(distinct))
}

// TestCardinalityGuard_ObserverFiresOnOverflow confirms the observer
// callback runs exactly once per overflow event.
func TestCardinalityGuard_ObserverFiresOnOverflow(t *testing.T) {
	var fired int
	g := NewCardinalityGuard(1, func() { fired++ })
	_ = g.Normalize("keep")
	_ = g.Normalize("overflow-1")
	_ = g.Normalize("overflow-2")
	require.Equal(t, 2, fired)
}

// TestPrometheusMetrics_CardinalityCap verifies end-to-end that a
// PrometheusMetrics with WithCardinalityLimit(2) folds additional
// routes into the overflow bucket for the filter_decisions counter.
func TestPrometheusMetrics_CardinalityCap(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg).WithCardinalityLimit(2)

	m.RecordDecision("route-a", "backend-a", "tool", "pass")
	m.RecordDecision("route-b", "backend-b", "tool", "pass")
	m.RecordDecision("route-c", "backend-c", "tool", "pass") // overflow
	m.RecordDecision("route-d", "backend-d", "tool", "pass") // overflow

	// route-a and route-b land on their real tuples.
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-a", "backend-a", "tool", "pass")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-b", "backend-b", "tool", "pass")))

	// route-c and route-d go to the synthetic overflow bucket. The
	// count is 2 because both requests folded into the same tuple.
	require.Equal(t, 2.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues(
		CardinalityOverflowLabel, CardinalityOverflowLabel, CardinalityOverflowLabel, CardinalityOverflowLabel,
	)))

	require.Equal(t, int64(2), m.DecisionGuard().OverflowCount())
}
