// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

func TestPIIAdmission_CapacityClampsUp(t *testing.T) {
	a := NewPIIAdmission(0)
	require.Equal(t, 1, a.Capacity())
	a = NewPIIAdmission(-5)
	require.Equal(t, 1, a.Capacity())
}

func TestPIIAdmission_AcquireRelease(t *testing.T) {
	a := NewPIIAdmission(2)
	r1, err := a.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, a.Inflight())

	r2, err := a.Acquire(context.Background())
	require.NoError(t, err)
	require.Equal(t, 2, a.Inflight())

	r1()
	require.Equal(t, 1, a.Inflight())
	r2()
	require.Equal(t, 0, a.Inflight())
}

func TestPIIAdmission_TryAcquire_ShedsWhenFull(t *testing.T) {
	a := NewPIIAdmission(1)
	r, err := a.TryAcquire()
	require.NoError(t, err)

	_, err = a.TryAcquire()
	require.ErrorIs(t, err, ErrAdmissionShed)

	r()
	r2, err := a.TryAcquire()
	require.NoError(t, err)
	r2()
}

func TestPIIAdmission_NilIsNoop(t *testing.T) {
	var a *PIIAdmission
	require.Equal(t, 0, a.Capacity())
	require.Equal(t, 0, a.Inflight())
	r, err := a.Acquire(context.Background())
	require.NoError(t, err)
	require.NotNil(t, r)
	r() // must not panic
	r2, err := a.TryAcquire()
	require.NoError(t, err)
	require.NotNil(t, r2)
	r2()
}

// TestPIIAdmission_AcquireRespectsContextCancel verifies that
// blocking callers receive ctx.Err() promptly when cancellation fires
// while they wait on an empty pool.
func TestPIIAdmission_AcquireRespectsContextCancel(t *testing.T) {
	a := NewPIIAdmission(1)
	// Fill the one slot.
	r, err := a.Acquire(context.Background())
	require.NoError(t, err)
	defer r()

	// Second acquire must block; cancel it.
	ctx, cancel := context.WithCancel(context.Background())
	var got error
	done := make(chan struct{})
	go func() {
		_, got = a.Acquire(ctx)
		close(done)
	}()
	time.Sleep(10 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Acquire did not return after cancellation")
	}
	require.ErrorIs(t, got, context.Canceled)
}

// TestPIIAdmission_ConcurrentAcquirersRespectCap uses N>capacity
// goroutines and asserts the inflight counter never exceeds capacity.
func TestPIIAdmission_ConcurrentAcquirersRespectCap(t *testing.T) {
	const capacity = 4
	a := NewPIIAdmission(capacity)
	var peak atomic.Int64
	var wg sync.WaitGroup
	const N = 32
	for range N {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := a.Acquire(context.Background())
			require.NoError(t, err)
			defer r()
			now := int64(a.Inflight())
			for {
				prev := peak.Load()
				if now <= prev || peak.CompareAndSwap(prev, now) {
					break
				}
			}
			time.Sleep(time.Millisecond)
		}()
	}
	wg.Wait()
	require.LessOrEqual(t, int(peak.Load()), capacity,
		"in-flight exceeded capacity under concurrent Acquire")
	require.Equal(t, 0, a.Inflight())
}

// TestPIIAdmission_MetricsObserverInstalled exercises the Prometheus
// adapter to confirm gauges and shed counts are emitted as expected.
func TestPIIAdmission_MetricsObserverInstalled(t *testing.T) {
	pm := NewPrometheusMetrics(prometheus.NewRegistry())
	SetAdmissionMetrics(pm.AsAdmission())
	t.Cleanup(func() { SetAdmissionMetrics(nil) })

	a := NewPIIAdmission(2)
	r, err := a.Acquire(context.Background())
	require.NoError(t, err)
	// Inflight gauge should be 1.
	inflight := testutil.ToFloat64(pm.filterInflight.WithLabelValues("_global_", "pii_admission"))
	require.Equal(t, 1.0, inflight)

	r()
	inflight = testutil.ToFloat64(pm.filterInflight.WithLabelValues("_global_", "pii_admission"))
	require.Equal(t, 0.0, inflight)

	// Fill + shed.
	r1, err := a.TryAcquire()
	require.NoError(t, err)
	defer r1()
	r2, err := a.TryAcquire()
	require.NoError(t, err)
	defer r2()
	_, err = a.TryAcquire()
	require.ErrorIs(t, err, ErrAdmissionShed)
	shed := testutil.ToFloat64(pm.filterDecisions.WithLabelValues("_global_", "pii_admission", "_admission_", "shed"))
	require.Equal(t, 1.0, shed)
}
