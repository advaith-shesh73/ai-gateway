// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"errors"
	"sync/atomic"
)

// ErrAdmissionShed is returned when the global PII admission
// semaphore is saturated and the caller asked for non-blocking
// admission (i.e. "shed to fallback if there is no slot right now").
// Handlers convert this into a fail-open fallback rather than
// blocking the caller on back-pressure they cannot usefully consume.
var ErrAdmissionShed = errors.New("mcpproxy: admission shed (queue full)")

// PIIAdmission is a process-global concurrency gate that bounds the
// number of in-flight PII anonymize calls across ALL routes and
// backends. It exists because:
//
//  1. Without it, a traffic burst can fan out an arbitrary number of
//     concurrent PII requests per process (each Anonymize call can
//     itself fan out up to MaxParallelChunks chunks). Unbounded
//     concurrency here has been observed to exhaust the PII sidecar's
//     worker pool AND the gateway's own conn pool, which then cascades
//     into unrelated handler latency.
//  2. A single Prometheus gauge tracking queue depth and in-flight is
//     easier to alert on than N per-route semaphores.
//
// Semantics:
//   - Acquire blocks until a slot is available OR ctx is canceled.
//     Returns the acquired release function on success.
//   - TryAcquire is non-blocking: returns (release, nil) if a slot
//     was available, (nil, ErrAdmissionShed) otherwise. Callers that
//     want to fall through to fail-open fallback on back-pressure
//     use this form.
//   - The zero-valued PIIAdmission is NOT safe to use; call
//     NewPIIAdmission.
//
// The implementation is a buffered channel (capacity = MaxInFlight),
// which is simpler and cheaper than sync.Mutex + counter and gives
// us FIFO admission for free. On every admit/release it updates the
// mcp_filter_queue_depth and mcp_filter_inflight gauges (if a metrics
// observer has been installed via SetAdmissionMetrics).
type PIIAdmission struct {
	slots    chan struct{}
	inflight atomic.Int64
	cap      int
}

// PIIAdmissionMetrics is the observer interface for admission events.
// Implementations are expected to be cheap: a single gauge set per
// call. nil is a valid (no-op) observer.
type PIIAdmissionMetrics interface {
	// SetInflight records the current number of acquired slots.
	SetInflight(n int)
	// SetQueueDepth records the number of goroutines waiting for a
	// slot. Only ever reported approximately because Go's channel
	// API doesn't expose the waiter count — see Acquire for the
	// exact accounting.
	SetQueueDepth(n int)
	// RecordShed increments a counter whenever TryAcquire returns
	// ErrAdmissionShed. Useful for alerting on back-pressure.
	RecordShed()
}

var admissionMetrics atomic.Pointer[piiAdmissionMetricsBox]

type piiAdmissionMetricsBox struct{ m PIIAdmissionMetrics }

// SetAdmissionMetrics installs a process-wide observer for admission
// events. Pass nil to clear. Safe to call at any time from any
// goroutine. Typical wiring from bootstrap:
//
//	m := NewPrometheusMetrics(registry)
//	SetAdmissionMetrics(m.AsAdmission())
func SetAdmissionMetrics(m PIIAdmissionMetrics) {
	if m == nil {
		admissionMetrics.Store(nil)
		return
	}
	admissionMetrics.Store(&piiAdmissionMetricsBox{m: m})
}

func admissionMetricsLoad() PIIAdmissionMetrics {
	b := admissionMetrics.Load()
	if b == nil {
		return nil
	}
	return b.m
}

// NewPIIAdmission returns an admission gate sized at maxInFlight.
// maxInFlight <= 0 is clamped to 1 so the pipeline never locks up.
func NewPIIAdmission(maxInFlight int) *PIIAdmission {
	if maxInFlight < 1 {
		maxInFlight = 1
	}
	return &PIIAdmission{
		slots: make(chan struct{}, maxInFlight),
		cap:   maxInFlight,
	}
}

// Capacity returns the configured maximum number of in-flight slots.
func (a *PIIAdmission) Capacity() int {
	if a == nil {
		return 0
	}
	return a.cap
}

// Inflight returns the current number of acquired slots (0 ≤ n ≤ Capacity).
func (a *PIIAdmission) Inflight() int {
	if a == nil {
		return 0
	}
	return int(a.inflight.Load())
}

// Acquire blocks until a slot is free or ctx is canceled. Returns the
// release function on success. A nil a is a no-op (returns a no-op
// release) so callers can unconditionally invoke Acquire regardless
// of whether admission is configured.
//
// Cancellation during a wait returns (nil, ctx.Err()). Callers MUST
// treat this as "failed to admit" and NOT call the returned release.
func (a *PIIAdmission) Acquire(ctx context.Context) (release func(), err error) {
	if a == nil {
		return func() {}, nil
	}
	// Best-effort queue-depth observation: the difference between
	// current in-flight and capacity is the upper bound on waiters,
	// but we can't observe actual waiter count without a separate
	// counter. Keep this honest as "slots unavailable" rather than
	// "goroutines waiting" — the label name in Prometheus is
	// `stage=pii_admission` so the distinction is clear on the
	// dashboard.
	select {
	case a.slots <- struct{}{}:
		n := a.inflight.Add(1)
		if m := admissionMetricsLoad(); m != nil {
			m.SetInflight(int(n))
		}
		return a.release, nil
	default:
	}
	// Slow path: no slot available; update queue depth approximation.
	if m := admissionMetricsLoad(); m != nil {
		m.SetQueueDepth(a.cap)
	}
	select {
	case a.slots <- struct{}{}:
		n := a.inflight.Add(1)
		if m := admissionMetricsLoad(); m != nil {
			m.SetInflight(int(n))
			// Depth dropped now that we admitted.
			m.SetQueueDepth(a.cap - int(n))
		}
		return a.release, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TryAcquire is the non-blocking variant. Returns (release, nil) on
// success. Returns (nil, ErrAdmissionShed) when all slots are busy —
// this is the "shed to fallback" signal that handlers use to return
// the original text instead of blocking on back-pressure.
func (a *PIIAdmission) TryAcquire() (release func(), err error) {
	if a == nil {
		return func() {}, nil
	}
	select {
	case a.slots <- struct{}{}:
		n := a.inflight.Add(1)
		if m := admissionMetricsLoad(); m != nil {
			m.SetInflight(int(n))
		}
		return a.release, nil
	default:
		if m := admissionMetricsLoad(); m != nil {
			m.RecordShed()
		}
		return nil, ErrAdmissionShed
	}
}

// release drops a slot back into the pool. It is idempotent only in
// the sense that double-calling it is a programmer error that
// over-releases; the buffered channel panics are not raised because
// receiving from a full buffered channel is well-defined, but the
// inflight counter will be wrong. The happy path is always:
//
//	release, err := adm.Acquire(ctx)
//	if err != nil { return err }
//	defer release()
//
// Ordering note: we decrement the inflight counter BEFORE draining
// the channel token. The opposite ordering (drain-then-decrement)
// has a race where a concurrent Acquire — which can now see an open
// channel slot — pushes its token and bumps inflight above Capacity()
// before the releaser's decrement lands. The channel capacity still
// enforces strict ≤ cap concurrent holders, but external observers
// of Inflight() would see a momentary over-report that would trip
// saturation alarms. Decrementing first means observers may see a
// slight under-report (counter=n, but the n+1-th slot is still
// "holding its token"), which is always safe because the concurrent
// acquirer is guaranteed to block on a full channel until this
// function drains its token.
func (a *PIIAdmission) release() {
	prev := a.inflight.Add(-1)
	if prev < 0 {
		// Over-release: undo and bail without touching the channel.
		// Clamp to 0 so the gauge stays non-negative. A legitimate
		// holder always incremented the counter in Acquire, so a
		// negative value here means double-release; the channel
		// slot (if any) belongs to nobody.
		a.inflight.Store(0)
		return
	}
	select {
	case <-a.slots:
		// Freed the slot. A waiter on the slow path can now be
		// admitted; its increment lands after ours here.
	default:
		// Channel empty despite a positive counter. Should not
		// happen in normal operation; drop silently rather than
		// deadlocking. The counter is already corrected above.
	}
	if m := admissionMetricsLoad(); m != nil {
		m.SetInflight(int(prev))
	}
}
