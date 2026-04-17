// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestPrometheusMetrics_RegistersAllFourteenVectors exercises the
// headline guarantee of L03: every one of the 14 metric names is
// present in the registry after construction.
//
// Prometheus only emits a metric family in Gather() after it has been
// written to at least once, so the test seeds one observation per
// vector before scanning. That matches production reality — these
// vectors will be written before any scrape lands.
func TestPrometheusMetrics_RegistersAllFourteenVectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	// Seed one observation per vector so Gather() surfaces it.
	pii := m.AsPII()
	pii.RecordCall("ok", "ctx")
	pii.ObserveCallDuration(0, "ctx")
	pii.ObserveChunkFanout(1, "ctx")
	pii.AddBytes(1, "ctx")
	pii.RecordCacheLookup("pii", "hit")
	jira := m.AsJira()
	jira.RecordCall("ok", "op")
	jira.ObserveCallDuration(0, "op")
	br := m.AsBreaker()
	br.OnState("pii", CircuitClosed)
	br.OnTransition("pii", CircuitClosed, CircuitOpen)
	m.RecordDecision("r", "b", ScopeRequest, ActionPass)
	m.RecordStatus("r", "b", "ok")
	m.IncInflight("r", "b")
	m.SetQueueDepth("s", 0)
	m.RecordPanic("w")

	families, err := reg.Gather()
	require.NoError(t, err)

	want := []string{
		"pii_calls_total",
		"pii_call_duration_seconds",
		"pii_chunks_total",
		"pii_bytes_total",
		"cache_lookups_total",
		"jira_calls_total",
		"jira_call_duration_seconds",
		"mcp_filter_circuit_state",
		"mcp_filter_circuit_transitions_total",
		"mcp_filter_decisions_total",
		"mcp_filter_status_total",
		"mcp_filter_inflight",
		"mcp_filter_queue_depth",
		"mcp_filter_worker_panics_total",
	}
	got := map[string]bool{}
	for _, f := range families {
		got[f.GetName()] = true
	}
	for _, n := range want {
		require.True(t, got[n], "metric %q must be registered", n)
	}
	require.Len(t, got, len(want), "exactly %d metrics expected, got %v", len(want), got)
}

// TestPrometheusMetrics_DoubleRegisterPanics documents the contract
// that the constructor must NOT be called twice with the same
// registry. Using a fresh [prometheus.NewRegistry] per instance is
// the canonical pattern.
func TestPrometheusMetrics_DoubleRegisterPanics(t *testing.T) {
	reg := prometheus.NewRegistry()
	_ = NewPrometheusMetrics(reg)

	defer func() {
		r := recover()
		require.NotNil(t, r, "second NewPrometheusMetrics on the same registry must panic")
	}()
	_ = NewPrometheusMetrics(reg)
}

// TestPrometheusMetrics_AsPII_EmitsOnAllFiveMetrics ensures the PII
// adapter hits every PIIMetrics-mapped vector once, with the right
// labels.
func TestPrometheusMetrics_AsPII_EmitsOnAllFiveMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	pii := m.AsPII()

	pii.RecordCall("ok", "ctx-a")
	pii.RecordCall("timeout", "ctx-b")
	pii.ObserveCallDuration(150*time.Millisecond, "ctx-a")
	pii.ObserveChunkFanout(3, "ctx-a")
	pii.AddBytes(1234, "ctx-a")
	pii.RecordCacheLookup("pii", "hit")
	pii.RecordCacheLookup("pii", "miss")

	require.Equal(t, 1.0, testutil.ToFloat64(m.piiCalls.WithLabelValues("ok", "ctx-a")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.piiCalls.WithLabelValues("timeout", "ctx-b")))
	require.Equal(t, 1234.0, testutil.ToFloat64(m.piiBytes.WithLabelValues("ctx-a")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.cacheLookups.WithLabelValues("pii", "hit")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.cacheLookups.WithLabelValues("pii", "miss")))

	// Histograms: assert at least one observation was recorded.
	dur, err := reg.Gather()
	require.NoError(t, err)
	var sawDur, sawChunks bool
	for _, f := range dur {
		if f.GetName() == "pii_call_duration_seconds" && len(f.GetMetric()) > 0 {
			sawDur = true
		}
		if f.GetName() == "pii_chunks_total" && len(f.GetMetric()) > 0 {
			sawChunks = true
		}
	}
	require.True(t, sawDur, "pii_call_duration_seconds must see at least one observation")
	require.True(t, sawChunks, "pii_chunks_total must see at least one observation")
}

// TestPrometheusMetrics_AsJira_EmitsOnBothMetrics mirrors the PII
// check for the Jira adapter.
func TestPrometheusMetrics_AsJira_EmitsOnBothMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	jira := m.AsJira()

	jira.RecordCall("ok", "fetch_issue")
	jira.RecordCall("http_error", "fetch_issue")
	jira.ObserveCallDuration(50*time.Millisecond, "fetch_issue")

	require.Equal(t, 1.0, testutil.ToFloat64(m.jiraCalls.WithLabelValues("ok", "fetch_issue")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.jiraCalls.WithLabelValues("http_error", "fetch_issue")))
}

// TestPrometheusMetrics_AsBreaker_PublishesStateAndTransitions verifies
// the breaker adapter updates the state gauge (latest-wins) and the
// transitions counter (monotonic).
func TestPrometheusMetrics_AsBreaker_PublishesStateAndTransitions(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	br := m.AsBreaker()

	br.OnState("pii", CircuitClosed)
	br.OnTransition("pii", CircuitClosed, CircuitOpen)
	br.OnState("pii", CircuitOpen)
	br.OnTransition("pii", CircuitOpen, CircuitHalfOpen)
	br.OnState("pii", CircuitHalfOpen)
	br.OnTransition("pii", CircuitHalfOpen, CircuitClosed)
	br.OnState("pii", CircuitClosed)

	require.Equal(t, float64(CircuitClosed), testutil.ToFloat64(m.circuitState.WithLabelValues("pii")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.circuitTransitions.WithLabelValues("pii", "closed", "open")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.circuitTransitions.WithLabelValues("pii", "open", "half_open")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.circuitTransitions.WithLabelValues("pii", "half_open", "closed")))
}

// TestPrometheusMetrics_RecordDecisionAndStatus exercises the
// dispatcher-oriented convenience methods.
func TestPrometheusMetrics_RecordDecisionAndStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	m.RecordDecision("route-a", "supportgpt", ScopeResponse, ActionRedact)
	m.RecordDecision("route-a", "supportgpt", ScopeResponse, ActionPass)
	m.RecordDecision("route-b", "nurag", ScopeRequest, ActionReject)
	m.RecordStatus("route-a", "supportgpt", "redacted")
	m.RecordStatus("route-a", "supportgpt", "passthrough")

	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-a", "supportgpt", "Response", "redact")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-a", "supportgpt", "Response", "pass")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-b", "nurag", "Request", "reject")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterStatus.WithLabelValues("route-a", "supportgpt", "redacted")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterStatus.WithLabelValues("route-a", "supportgpt", "passthrough")))
}

// TestPrometheusMetrics_InflightAndQueueDepthGauges confirms the
// saturation gauges round-trip values correctly.
func TestPrometheusMetrics_InflightAndQueueDepthGauges(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	m.IncInflight("route-a", "supportgpt")
	m.IncInflight("route-a", "supportgpt")
	m.IncInflight("route-a", "supportgpt")
	m.DecInflight("route-a", "supportgpt")
	require.Equal(t, 2.0, testutil.ToFloat64(m.filterInflight.WithLabelValues("route-a", "supportgpt")))

	m.SetQueueDepth("pii-admission", 42)
	require.Equal(t, 42.0, testutil.ToFloat64(m.filterQueueDepth.WithLabelValues("pii-admission")))

	m.SetQueueDepth("pii-admission", 0)
	require.Equal(t, 0.0, testutil.ToFloat64(m.filterQueueDepth.WithLabelValues("pii-admission")))
}

// TestPrometheusMetrics_RecordPanic exercises the L07 follow-up:
// every panic surfaced by safeGo increments the worker-panic counter.
func TestPrometheusMetrics_RecordPanic(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	m.RecordPanic("pii chunk worker")
	m.RecordPanic("pii chunk worker")
	m.RecordPanic("scan part worker")
	require.Equal(t, 2.0, testutil.ToFloat64(m.workerPanics.WithLabelValues("pii chunk worker")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.workerPanics.WithLabelValues("scan part worker")))
}

// TestSetPanicRecorder_WiresSafeGoToMetrics verifies the
// [SetPanicRecorder] hook is actually invoked from [safeGo] when a
// worker panics. This is the glue that connects L07 (panic recovery)
// to L03 (metrics registry).
func TestSetPanicRecorder_WiresSafeGoToMetrics(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	// Install, tear down via t.Cleanup so we don't leak into later
	// tests.
	SetPanicRecorder(m.RecordPanic)
	t.Cleanup(func() { SetPanicRecorder(nil) })

	err := safeGo("boom worker", func() error {
		panic("intentional panic for test")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "boom worker panic")
	require.InDelta(t, 1.0, testutil.ToFloat64(m.workerPanics.WithLabelValues("boom worker")), 0.0001)
}

// TestSetPanicRecorder_NilIsSafe guards against regressions where a
// nil callback would panic inside the recover path (which would then
// poison the goroutine that was meant to survive).
func TestSetPanicRecorder_NilIsSafe(t *testing.T) {
	SetPanicRecorder(nil)
	err := safeGo("still boom", func() error { panic("x") })
	require.Error(t, err)
}

// TestPrometheusMetrics_NilReceiverIsInert ensures the metric-emitting
// convenience methods are no-ops on a nil receiver. This matches the
// Dispatcher's code path where metrics may not be wired in tests.
func TestPrometheusMetrics_NilReceiverIsInert(_ *testing.T) {
	var m *PrometheusMetrics // nil
	// None of these must panic or allocate observable state.
	m.RecordDecision("r", "b", ScopeRequest, ActionPass)
	m.RecordStatus("r", "b", "ok")
	m.IncInflight("r", "b")
	m.DecInflight("r", "b")
	m.SetQueueDepth("s", 1)
	m.RecordPanic("w")
}

// TestPrometheusMetrics_EmptyLabelFlattensToDash verifies the
// labelOrDash substitution survives the round trip. An empty route
// would otherwise break Prometheus-side label grouping.
func TestPrometheusMetrics_EmptyLabelFlattensToDash(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	m.RecordDecision("", "", ScopeRequest, ActionPass)
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("-", "-", "Request", "pass")))
}
