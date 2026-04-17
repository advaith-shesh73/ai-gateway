// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"strings"
	"sync"
	"sync/atomic"
)

// CardinalityOverflowLabel is the sentinel value substituted for any
// label tuple that appears after the guard has hit its cap. The
// underscores on both sides mean it sorts to the extremes of any
// alphabetically-ordered label-set dashboards and won't collide with
// real route/backend names (which don't contain underscores).
const CardinalityOverflowLabel = "_overflow_"

// CardinalityGuard bounds the number of unique label tuples a metric
// can emit. When the cap is reached, any new tuple is rewritten to
// the all-`_overflow_` synthetic tuple instead of being emitted
// verbatim. Existing tuples continue to flow through unchanged so
// in-progress requests keep their metrics coherent.
//
// Why this matters: Prometheus stores a time-series per unique label
// tuple. Emitting an unbounded set of tuples (route-per-tenant,
// backend-per-customer, etc.) is the #1 way to OOM the scraper. The
// guard lets you keep the useful cardinality (top-N routes) while
// guaranteeing the metric cannot explode past `cap` tuples.
//
// Typical cap sizes: O(hundreds) for route/backend metrics,
// O(thousands) for label combinations that include tool names. The
// guard is intended as a safety net, not a first-line budget — keep
// the cap 2-3x the expected unique tuples in steady state.
//
// Zero value is not usable: call NewCardinalityGuard.
type CardinalityGuard struct {
	mu       sync.RWMutex
	seen     map[string]struct{}
	capacity int
	overflow atomic.Int64

	// observer fires once per transition from "not overflowed" to
	// "overflowed" on a specific tuple. Useful for installing an
	// alerting gauge.
	observer func()
}

// NewCardinalityGuard returns a guard with the given capacity. A
// capacity <= 0 clamps to 1 so the guard never divides-by-zero;
// callers that want "effectively unbounded" should pass
// math.MaxInt32 explicitly. The observer callback, when non-nil, is
// invoked once each time a new tuple overflows (i.e. is replaced with
// the sentinel). Observers must not block — run heavy work
// asynchronously.
func NewCardinalityGuard(capacity int, observer func()) *CardinalityGuard {
	if capacity < 1 {
		capacity = 1
	}
	return &CardinalityGuard{
		seen:     make(map[string]struct{}, capacity),
		capacity: capacity,
		observer: observer,
	}
}

// Normalize returns the label tuple to emit. If the input tuple has
// been seen before OR there is room in the guard, it returns the
// input verbatim and records the tuple. Otherwise it returns a
// same-length slice where every element is [CardinalityOverflowLabel]
// and increments the overflow counter.
//
// The contract is stable: for any given input tuple, the same output
// is returned forever. That means Inc/Dec gauge pairs that share the
// same input will always land on the same emitted tuple.
func (g *CardinalityGuard) Normalize(labels ...string) []string {
	if g == nil {
		return labels
	}
	key := joinKey(labels)

	// Fast path: already-seen tuples return immediately under a
	// read lock. This is the overwhelmingly common case on hot
	// endpoints.
	g.mu.RLock()
	if _, ok := g.seen[key]; ok {
		g.mu.RUnlock()
		return labels
	}
	g.mu.RUnlock()

	// Slow path: unknown tuple; either admit it or overflow. Do
	// the work under a write lock and re-check membership to avoid
	// a TOCTOU racing with another goroutine admitting the same
	// key first.
	g.mu.Lock()
	if _, ok := g.seen[key]; ok {
		g.mu.Unlock()
		return labels
	}
	if len(g.seen) >= g.capacity {
		g.mu.Unlock()
		g.overflow.Add(1)
		if g.observer != nil {
			g.observer()
		}
		return overflowLabels(len(labels))
	}
	g.seen[key] = struct{}{}
	g.mu.Unlock()
	return labels
}

// OverflowCount returns the total number of label tuples that have
// been rewritten to [CardinalityOverflowLabel] since the guard was
// created. Useful for regression tests and for exposing as a
// separate Prometheus counter.
func (g *CardinalityGuard) OverflowCount() int64 {
	if g == nil {
		return 0
	}
	return g.overflow.Load()
}

// SeenCount returns the current number of distinct label tuples the
// guard has admitted. Once this reaches [CardinalityGuard.Cap] no
// further distinct tuples are admitted until Reset is called.
func (g *CardinalityGuard) SeenCount() int {
	if g == nil {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.seen)
}

// Cap returns the configured capacity.
func (g *CardinalityGuard) Cap() int {
	if g == nil {
		return 0
	}
	return g.capacity
}

// Reset clears the admitted-tuple set so the guard starts fresh. The
// overflow counter is preserved (it is a running total across resets
// for alerting purposes — clear it explicitly if your use case needs
// that). Intended use: when operators have verified the cardinality
// surge has stopped and want to re-admit tuples.
func (g *CardinalityGuard) Reset() {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen = make(map[string]struct{}, g.capacity)
}

// joinKey concatenates labels with a NUL separator. NUL cannot appear
// in a Prometheus label value, so it uniquely separates components
// without the allocation overhead of building a map or tuple.
func joinKey(labels []string) string {
	// Fast path for the most common case (3 labels: route/backend/tool
	// or route/backend/action).
	switch len(labels) {
	case 0:
		return ""
	case 1:
		return labels[0]
	case 2:
		return labels[0] + "\x00" + labels[1]
	case 3:
		return labels[0] + "\x00" + labels[1] + "\x00" + labels[2]
	default:
		var b strings.Builder
		size := len(labels) - 1 // for the separators
		for _, s := range labels {
			size += len(s)
		}
		b.Grow(size)
		for i, s := range labels {
			if i > 0 {
				b.WriteByte(0)
			}
			b.WriteString(s)
		}
		return b.String()
	}
}

// overflowLabels returns a fresh slice of length n filled with the
// overflow sentinel. Used when the guard has hit its cap.
func overflowLabels(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = CardinalityOverflowLabel
	}
	return out
}
