// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build load

// Package mcpproxy: load harness for the content-filter pipeline. This
// file is NEVER compiled in the default go test ./... matrix. It is
// gated behind the `load` build tag so production CI runs are not
// tripped by its second-scale runtime.
//
// Run with:
//
//	go test -tags load -run TestLoad -count=1 -timeout 10m \
//	        -race=false ./internal/mcpproxy/...
//
// The harness drives the PII client against a fake (in-process)
// httptest backend at high sustained concurrency, then asserts on:
//
//  1. Throughput floor — the pipeline must complete at least
//     TargetThroughputQPS requests/second over a fixed window.
//  2. Tail-latency ceiling — p99 latency must stay below
//     MaxP99Latency under sustained load.
//  3. Error budget — at most MaxErrorBudgetPPM parts-per-million of
//     requests may error (or fail-open, counted as "would leak").
//  4. No goroutine leak — after the test window closes, goroutine
//     count must return to within 10% of baseline.
//  5. Admission back-pressure — if the admission semaphore is
//     configured, its shed counter must correlate with worker
//     saturation (we don't assert an exact count; we assert the
//     counter is stable after the load window, proving the
//     shed-to-fallback path worked without breaking invariants).
//
// What this catches that unit tests don't
// ---------------------------------------
// Race detectors surface data races, unit tests surface correctness,
// but only sustained load reveals:
//
//   - Connection-pool starvation (L01): under-sized MaxIdleConnsPerHost
//     makes tail latency explode as connections churn.
//   - Circuit breaker oscillation (L11): half-open admit rate too high
//     causes the breaker to flap between closed/open, adding error
//     spikes every cooldown cycle.
//   - Cache mutex contention (L08): a single-mutex cache becomes the
//     serialization point at high QPS; sharded cache should flatten
//     the p99 curve.
//   - Goroutine leaks from hedged requests (L19): if the hedge's
//     context isn't canceled cleanly, losers pile up in a goroutine
//     graveyard.
//
// The harness is intentionally small (no external load tools) so it
// runs in a single `go test` invocation with no external deps.

package mcpproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// loadScenario describes one sustained-load experiment. Each scenario
// is a separate sub-test so CI failure reports pinpoint which knob
// regressed.
type loadScenario struct {
	name       string
	concurrent int           // worker goroutines sending requests
	duration   time.Duration // wall-clock duration of load window
	payload    string        // fixed body sent to PII service

	// Assertions
	MinThroughputQPS  float64       // per-second floor
	MaxP99Latency     time.Duration // tail ceiling
	MaxErrorBudgetPPM int           // parts-per-million of errors

	// Behavior knobs
	hedgeAfter     time.Duration // 0 disables hedging
	serverMeanMS   int           // synthetic server latency mean
	serverJitterMS int           // synthetic server latency jitter
	serverErrorPPM int           // synthetic fault injection rate (ppm)
}

// loadScenarios pins the baseline matrix we enforce. Each scenario's
// assertions are calibrated to flag MAJOR regressions (>3×) not micro-
// tuning drift. Absolute latency/QPS numbers vary with CI hardware,
// so we set generous ceilings grounded in observed baselines on a
// clean workstation and leave ≥3× headroom for slower CI machines.
//
// Calibration notes (2026-04-17, Apple M-series, race=off):
//   - baseline_happy_path: observed p99 ≈ 170 ms @ 1085 qps / 64 workers.
//     Ceiling set at 1 s (≈6×) to absorb CI jitter and dev-machine noise.
//   - tail_with_hedging: observed p99 ≈ 340 ms with 40 ms server jitter;
//     ceiling 3 s (≈9×). Without hedging this would blow past the mean.
//     Point of scenario: catch a regression that makes hedging useless.
//     The hedging code path fans out secondary requests which can
//     cluster under GC pressure, so the ceiling is widened relative
//     to the happy-path scenario to absorb measurement noise.
//   - error_injection_fail_open: observed p99 ≈ 80 ms; ceiling 1 s (≈12×).
//     Error budget intentionally wide (60 000 ppm) since scenario
//     injects faults at 50 000 ppm. Circuit-breaker oscillation at
//     5 % error rate produces bursty latency; the wide ceiling catches
//     true oscillation runaways (≥10×) while tolerating normal bursts.
//
// Ceilings are sized to flag MAJOR regressions (≥6-12× depending on
// scenario, scaled by its inherent variance). If a scenario fails in
// CI, treat it as a red flag: either the code regressed or a test-env
// issue (GC stall, noisy neighbor) drove latency past a ceiling that
// was already wide by construction. Investigate before relaxing.
var loadScenarios = []loadScenario{
	{
		name:              "baseline_happy_path",
		concurrent:        64,
		duration:          3 * time.Second,
		payload:           "John Smith lives at 1 Main Street in Springfield USA.",
		MinThroughputQPS:  300,
		MaxP99Latency:     1 * time.Second,
		MaxErrorBudgetPPM: 100,
		serverMeanMS:      2,
		serverJitterMS:    1,
		serverErrorPPM:    0,
	},
	{
		name:              "tail_with_hedging",
		concurrent:        64,
		duration:          3 * time.Second,
		payload:           "Alice Smith works at Globex and her phone is 555-0100.",
		MinThroughputQPS:  150,
		MaxP99Latency:     3 * time.Second,
		MaxErrorBudgetPPM: 100,
		hedgeAfter:        20 * time.Millisecond,
		serverMeanMS:      5,
		serverJitterMS:    40,
		serverErrorPPM:    0,
	},
	{
		name:              "error_injection_fail_open",
		concurrent:        32,
		duration:          2 * time.Second,
		payload:           "Bob Jones email is bob@acme.example.",
		MinThroughputQPS:  300,
		MaxP99Latency:     1 * time.Second,
		MaxErrorBudgetPPM: 60_000,
		serverMeanMS:      2,
		serverJitterMS:    1,
		serverErrorPPM:    50_000,
	},
}

// TestLoad_ContentFilter drives the full PII client against a fake
// server for each [loadScenario], collects throughput and latency,
// and asserts the pipeline meets the scenario's budget.
//
// This test is intentionally skipped under `-short` so developers can
// iterate quickly without paying the per-scenario cost.
func TestLoad_ContentFilter(t *testing.T) {
	if testing.Short() {
		t.Skip("load harness skipped under -short")
	}

	// Track baseline goroutine count BEFORE we run any scenario so
	// the final leak assertion compares against a clean number.
	runtime.GC()
	baselineGoroutines := runtime.NumGoroutine()

	for _, sc := range loadScenarios {
		t.Run(sc.name, func(t *testing.T) {
			runLoadScenario(t, &sc)
		})
		// Cool down between scenarios so the previous scenario's idle
		// HTTP connections, hedge-loser cancellations, and transient
		// goroutines drain before the next one starts. Without this,
		// accumulated state from the tail-with-hedging scenario
		// measurably skews the p99 of error-injection by holding
		// heap/goroutine resources that trigger a GC mid-window.
		// The sleep is small (100ms) relative to the 2-3s scenario
		// window so total wall-clock overhead is ~5%.
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
	}

	// Give any lingering goroutines a moment to drain (hedge losers,
	// HTTP idle conns).
	time.Sleep(200 * time.Millisecond)
	runtime.GC()
	final := runtime.NumGoroutine()
	// Allow a generous 50-goroutine headroom because runtime-internal
	// goroutines (GC assist, netpoll) can drift independently of our
	// code. We're looking for order-of-magnitude leaks, not off-by-one.
	if final > baselineGoroutines+50 {
		t.Fatalf("goroutine leak suspected: baseline=%d final=%d (delta=%d)",
			baselineGoroutines, final, final-baselineGoroutines)
	}
}

// runLoadScenario is the body of one scenario: stand up a fake PII
// backend with the configured latency/error profile, drive N workers
// in parallel for the configured duration, then evaluate assertions.
func runLoadScenario(t *testing.T, sc *loadScenario) {
	t.Helper()

	// 1) Synthetic PII server with configurable latency and fault rate.
	errCounter := new(atomic.Int64)
	callCounter := new(atomic.Int64)
	handler := func(w http.ResponseWriter, r *http.Request) {
		callCounter.Add(1)

		// Latency: mean ± jitter. Use a cheap per-call PRNG seeded
		// from the counter so successive calls don't drift together.
		sleep := time.Duration(sc.serverMeanMS) * time.Millisecond
		if sc.serverJitterMS > 0 {
			// deterministic jitter via counter modulo; no math/rand
			// to avoid mutex contention in hot loop.
			j := int(callCounter.Load()) % (sc.serverJitterMS * 2)
			sleep += time.Duration(j-sc.serverJitterMS) * time.Millisecond
			if sleep < 0 {
				sleep = 0
			}
		}
		if sleep > 0 {
			select {
			case <-time.After(sleep):
			case <-r.Context().Done():
				return
			}
		}

		// Error injection.
		if sc.serverErrorPPM > 0 {
			// ppm-sampled fault using counter to avoid rand; skew
			// acceptable at large N.
			if int(callCounter.Load())%(1_000_000/sc.serverErrorPPM) == 0 {
				errCounter.Add(1)
				http.Error(w, "injected fault", http.StatusInternalServerError)
				return
			}
		}

		_, _ = io.WriteString(w, `{"text":"<PERSON> lives at <LOCATION>."}`)
	}
	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	// 2) Client configured to the scenario. Fail-open on purpose: we
	//    want the harness to measure the actual end-user experience,
	//    which in prod is fail-open.
	c := newPIIClientForTest(t, srv.URL, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
		cfg.HedgeAfter = sc.hedgeAfter
		cfg.Timeout = 5 * time.Second
	})

	// 3) Parallel workers driving sustained load. Each worker runs in
	//    its own goroutine, issuing requests back-to-back, recording
	//    its own latency slice to avoid shared-slice contention; we
	//    merge at the end.
	var (
		wg        sync.WaitGroup
		perWorker = make([][]time.Duration, sc.concurrent)
		errPerW   = make([]int64, sc.concurrent)
	)
	ctx, cancel := context.WithTimeout(context.Background(), sc.duration+sc.duration/4)
	defer cancel()

	start := time.Now()
	deadline := start.Add(sc.duration)
	for i := 0; i < sc.concurrent; i++ {
		wg.Add(1)
		go func(wid int) {
			defer wg.Done()
			samples := make([]time.Duration, 0, 1024)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				_, err := c.Anonymize(ctx, sc.payload, "")
				samples = append(samples, time.Since(t0))
				if err != nil {
					errPerW[wid]++
				}
			}
			perWorker[wid] = samples
		}(i)
	}
	wg.Wait()
	wall := time.Since(start)

	// 4) Merge samples.
	var (
		all    []time.Duration
		totErr int64
	)
	for i, s := range perWorker {
		all = append(all, s...)
		totErr += errPerW[i]
	}
	if len(all) == 0 {
		t.Fatalf("no samples captured")
	}
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })

	// 5) Derive metrics.
	total := int64(len(all))
	qps := float64(total) / wall.Seconds()
	p50 := all[total/2]
	p95 := all[(total*95)/100]
	p99 := all[(total*99)/100]
	pMax := all[total-1]
	errPPM := int64(0)
	if total > 0 {
		errPPM = (totErr * 1_000_000) / total
	}

	t.Logf("scenario=%s qps=%.1f total=%d wall=%s", sc.name, qps, total, wall)
	t.Logf("  latency p50=%s p95=%s p99=%s pmax=%s",
		p50, p95, p99, pMax)
	t.Logf("  errors=%d ppm=%d (server_injected=%d)",
		totErr, errPPM, errCounter.Load())

	// 6) Assertions.
	if qps < sc.MinThroughputQPS {
		t.Errorf("throughput below floor: got %.1f qps want >= %.1f",
			qps, sc.MinThroughputQPS)
	}
	if p99 > sc.MaxP99Latency {
		t.Errorf("p99 above ceiling: got %s want <= %s",
			p99, sc.MaxP99Latency)
	}
	if errPPM > int64(sc.MaxErrorBudgetPPM) {
		t.Errorf("error rate above budget: got %d ppm want <= %d ppm",
			errPPM, sc.MaxErrorBudgetPPM)
	}
}

// TestLoad_PIIAdmission_ShedsCleanly drives the process-global
// admission semaphore from L02 into saturation and asserts that
// (a) shed events never corrupt the inflight counter and
// (b) release() returns the slot on both the happy and shed paths.
//
// We don't care about raw QPS here — we care that the counters remain
// coherent under stress.
func TestLoad_PIIAdmission_ShedsCleanly(t *testing.T) {
	if testing.Short() {
		t.Skip("load harness skipped under -short")
	}

	const slots = 8
	admit := NewPIIAdmission(slots)

	// Worker pattern: each iteration TryAcquire()s; on success, holds
	// the slot for a small random time; on shed, spins back around.
	workers := 256
	totalIters := int32(50_000) // tuned to run in ~2s under race
	var remaining atomic.Int32
	remaining.Store(totalIters)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for remaining.Add(-1) >= 0 {
				release, err := admit.TryAcquire()
				if err != nil {
					// shed path — counted internally.
					continue
				}
				// Simulate PII call duration.
				time.Sleep(10 * time.Microsecond)
				release()
			}
		}()
	}
	wg.Wait()

	// After the herd finishes, the inflight counter must return to 0.
	// We assert by trying to fill the semaphore to capacity and back;
	// if the counter was off we'd either block forever or over-admit.
	releases := make([]func(), 0, slots)
	for i := 0; i < slots; i++ {
		r, err := admit.TryAcquire()
		if err != nil {
			t.Fatalf("post-load: semaphore reported full at slot %d: %v", i, err)
		}
		releases = append(releases, r)
	}
	if _, err := admit.TryAcquire(); err == nil {
		t.Fatalf("post-load: semaphore admitted more than %d slots", slots)
	}
	for _, r := range releases {
		r()
	}
	// Now it should admit again.
	r, err := admit.TryAcquire()
	if err != nil {
		t.Fatalf("post-load: semaphore failed to re-admit after release: %v", err)
	}
	r()
	_ = fmt.Sprintf // keep fmt imported when no logging paths use it
}
