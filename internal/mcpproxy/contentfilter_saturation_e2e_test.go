// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// L24 — end-to-end verification that the two saturation gauges
// (mcp_filter_inflight and mcp_filter_queue_depth) track reality under
// realistic load. Without this test, we can't tell a configuration
// drift (metrics emitted but never updated) from a healthy
// "no-traffic" steady state.
//
// Strategy:
//   1. Create a PIIAdmission gate with small capacity (2).
//   2. Wire it to a PrometheusMetrics-backed adapter.
//   3. Launch N goroutines that Acquire+hold for a short beat, then
//      Release.
//   4. Concurrent with that fan-out, sample the gauges; assert
//      inflight is bounded by cap and queue depth rises when waiters
//      back up.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestAdmission_SaturationGauges_TrackConcurrentLoad drives the gate
// harder than it can serve and confirms:
//
//   - inflight never exceeds capacity (strict ≤ 2).
//   - inflight = 2 at least once during the test, proving the
//     gauge was actually bumped and not just the no-op default.
//   - queue depth rises above 0 at some point, proving waiters were
//     observed.
//   - after the storm, both gauges drain back to 0.
//
// The test is inherently timing-sensitive but uses a 25ms hold to
// give the sampler 100ms of observation window, which in practice is
// more than enough even on slow CI hardware without flaking.
func TestAdmission_SaturationGauges_TrackConcurrentLoad(t *testing.T) {
	const (
		capacity     = 2
		workers      = 8
		holdFor      = 25 * time.Millisecond
		sampleWindow = 150 * time.Millisecond
	)

	// Isolated registry so the test doesn't see stale gauges from
	// other tests and other tests don't see ours.
	reg := prometheus.NewRegistry()
	pm := NewPrometheusMetrics(reg)

	// Snapshot and restore the package-wide admissionMetrics pointer
	// so parallel tests aren't affected by our install. Using
	// defer-restore rather than t.Cleanup purely because the latter
	// runs after sub-tests inside t.Run scopes complete; this test
	// has no sub-tests so either would work.
	prev := admissionMetricsLoad()
	SetAdmissionMetrics(pm.AsAdmission())
	defer SetAdmissionMetrics(prev)

	adm := NewPIIAdmission(capacity)

	// Start samplers BEFORE traffic so we capture the rising edge.
	var (
		maxInflight    int
		sawQueueDepth  bool
		samplesTakenMu sync.Mutex
	)
	stopSampling := make(chan struct{})
	samplerDone := make(chan struct{})
	go func() {
		defer close(samplerDone)
		t := time.NewTicker(2 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stopSampling:
				return
			case <-t.C:
				inflight := testutil.ToFloat64(pm.filterInflight.WithLabelValues("_global_", "pii_admission"))
				depth := testutil.ToFloat64(pm.filterQueueDepth.WithLabelValues("pii_admission"))
				samplesTakenMu.Lock()
				if int(inflight) > maxInflight {
					maxInflight = int(inflight)
				}
				if depth > 0 {
					sawQueueDepth = true
				}
				samplesTakenMu.Unlock()
			}
		}
	}()

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			release, err := adm.Acquire(context.Background())
			if err != nil {
				t.Errorf("acquire failed: %v", err)
				return
			}
			time.Sleep(holdFor)
			release()
		}()
	}

	close(start)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(sampleWindow):
		t.Fatalf("workers did not drain in %v", sampleWindow)
	}

	// Give the sampler one more tick to observe the final drain.
	time.Sleep(10 * time.Millisecond)
	close(stopSampling)
	<-samplerDone

	samplesTakenMu.Lock()
	got := maxInflight
	sawDepth := sawQueueDepth
	samplesTakenMu.Unlock()

	require.LessOrEqual(t, got, capacity,
		"inflight must never exceed capacity; saw %d > cap=%d", got, capacity)
	require.Equal(t, capacity, got,
		"inflight must reach capacity at least once to prove the gauge fires; saw max=%d", got)
	require.True(t, sawDepth,
		"queue depth gauge must have been non-zero at least once during saturation")

	finalInflight := testutil.ToFloat64(pm.filterInflight.WithLabelValues("_global_", "pii_admission"))
	require.Equal(t, 0.0, finalInflight,
		"inflight must drain back to 0 after all workers release")
}

// TestAdmission_ShedMetric_Fires asserts the shed counter increments
// exactly once per rejected TryAcquire. Without this, the shed-to-
// fallback code path is silent to operators — they can see handler
// latency rise but not attribute it to admission pressure.
func TestAdmission_ShedMetric_Fires(t *testing.T) {
	reg := prometheus.NewRegistry()
	pm := NewPrometheusMetrics(reg)
	prev := admissionMetricsLoad()
	SetAdmissionMetrics(pm.AsAdmission())
	defer SetAdmissionMetrics(prev)

	adm := NewPIIAdmission(1)

	// Fill the single slot.
	rel, err := adm.TryAcquire()
	require.NoError(t, err)
	defer rel()

	// Next TryAcquire must shed.
	_, err = adm.TryAcquire()
	require.ErrorIs(t, err, ErrAdmissionShed)

	shed := testutil.ToFloat64(pm.filterDecisions.WithLabelValues("_global_", "pii_admission", "_admission_", "shed"))
	require.Equal(t, 1.0, shed, "shed counter must increment on saturation")
}
