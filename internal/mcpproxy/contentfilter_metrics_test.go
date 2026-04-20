// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)

// TestPrometheusMetrics_RegistersThreeFilterVectors exercises the
// headline guarantee of the gateway metrics surface: the three filter
// vectors (decisions, status, inflight) are all present in the
// registry after construction.
//
// Prometheus only emits a metric family in Gather() after it has been
// written to at least once, so the test seeds one observation per
// vector before scanning.
func TestPrometheusMetrics_RegistersThreeFilterVectors(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	m.RecordDecision("r", "b", ScopeRequest, ActionPass)
	m.RecordStatus("r", "b", "ok")
	m.IncInflight("r", "b")

	families, err := reg.Gather()
	require.NoError(t, err)

	want := []string{
		"mcp_filter_decisions_total",
		"mcp_filter_status_total",
		"mcp_filter_inflight",
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

// TestPrometheusMetrics_RecordDecisionAndStatus exercises the
// decisions + status counters the gateway emits after every filter
// round-trip.
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

// TestPrometheusMetrics_InflightGauge confirms the saturation gauge
// round-trips Inc/Dec correctly.
func TestPrometheusMetrics_InflightGauge(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)

	m.IncInflight("route-a", "supportgpt")
	m.IncInflight("route-a", "supportgpt")
	m.IncInflight("route-a", "supportgpt")
	m.DecInflight("route-a", "supportgpt")
	require.Equal(t, 2.0, testutil.ToFloat64(m.filterInflight.WithLabelValues("route-a", "supportgpt")))
}

// TestPrometheusMetrics_NilReceiverIsInert ensures the metric-emitting
// convenience methods are no-ops on a nil receiver. This matches
// gateway hot paths where metrics may not be wired in tests.
func TestPrometheusMetrics_NilReceiverIsInert(_ *testing.T) {
	var m *PrometheusMetrics
	m.RecordDecision("r", "b", ScopeRequest, ActionPass)
	m.RecordStatus("r", "b", "ok")
	m.IncInflight("r", "b")
	m.DecInflight("r", "b")
}

// TestPrometheusMetrics_EmptyLabelFlattensToDash verifies the
// labelOrDash substitution survives the round trip. An empty route
// would otherwise collapse into a single mystery series on Prometheus.
func TestPrometheusMetrics_EmptyLabelFlattensToDash(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	m.RecordDecision("", "", ScopeRequest, ActionPass)
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("-", "-", "Request", "pass")))
}

// TestPrometheusMetrics_CardinalityGuardRewritesOverflowTuples exercises
// the defense-in-depth cap: once the decisions guard is at capacity,
// new label tuples are rewritten to the overflow sentinel instead of
// exploding the series count.
func TestPrometheusMetrics_CardinalityGuardRewritesOverflowTuples(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg).WithCardinalityLimit(1)

	m.RecordDecision("r1", "b1", ScopeRequest, ActionPass)
	m.RecordDecision("r2", "b2", ScopeResponse, ActionRedact)

	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues("r1", "b1", "Request", "pass")))
	require.Equal(t, 1.0, testutil.ToFloat64(m.filterDecisions.WithLabelValues(
		CardinalityOverflowLabel, CardinalityOverflowLabel, CardinalityOverflowLabel, CardinalityOverflowLabel,
	)))
	require.EqualValues(t, 1, m.DecisionGuard().OverflowCount())
}
