// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// TestDispatcher_EmitsDecisionMetricOnEveryDispatch exercises the
// core L03 → Dispatcher wiring: every Dispatch call must bump the
// mcp_filter_decisions_total vector with the right (route, backend,
// scope, action) tuple.
func TestDispatcher_EmitsDecisionMetricOnEveryDispatch(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	require.NoError(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	d = d.WithMetrics(m)

	req := &FilterRequest{
		Route:     "route-a",
		Backend:   "unknown-backend",
		Scope:     ScopeRequest,
		MCPMethod: "tools/call",
		Tool:      "search",
		Headers:   NewHeaderView(nil),
	}

	_ = d.Dispatch(context.Background(), req, []byte(`{}`))
	_ = d.Dispatch(context.Background(), req, []byte(`{}`))
	// A different route / backend / scope / action combination.
	req2 := *req
	req2.Route = "route-b"
	req2.Scope = ScopeResponse
	_ = d.Dispatch(context.Background(), &req2, []byte(`{}`))

	require.Equal(t, 2.0,
		testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-a", "unknown-backend", "Request", "pass")),
		"two Request/pass decisions on route-a")

	require.Equal(t, 1.0,
		testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-b", "unknown-backend", "Response", "pass")),
		"one Response/pass decision on route-b")
}

// TestDispatcher_InflightGaugeBalancesOut verifies the Inc/Dec pair
// inside Dispatch always leaves the gauge at zero once all dispatches
// return. A missing defer would leak gauge count and be dashboard-
// visible within minutes.
func TestDispatcher_InflightGaugeBalancesOut(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	require.NoError(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	d = d.WithMetrics(m)

	req := &FilterRequest{
		Route:     "route-a",
		Backend:   "b",
		Scope:     ScopeRequest,
		MCPMethod: "tools/call",
		Headers:   NewHeaderView(nil),
	}

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_ = d.Dispatch(context.Background(), req, []byte(`{}`))
		}()
	}
	wg.Wait()

	require.Equal(t, 0.0,
		testutil.ToFloat64(m.filterInflight.WithLabelValues("route-a", "b")),
		"inflight gauge must return to 0 after all dispatches finish")
}

// TestDispatcher_UnknownScopeStillRecordsDecision guards against a
// regression where the unknown-scope branch would skip the decision
// counter and leave anomalies invisible to operators.
func TestDispatcher_UnknownScopeStillRecordsDecision(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	require.NoError(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	reg := prometheus.NewRegistry()
	m := NewPrometheusMetrics(reg)
	d = d.WithMetrics(m)

	req := &FilterRequest{
		Route:     "route-a",
		Backend:   "b",
		Scope:     Scope("Gibberish"),
		MCPMethod: "tools/call",
		Headers:   NewHeaderView(nil),
	}
	_ = d.Dispatch(context.Background(), req, []byte(`{}`))

	require.Equal(t, 1.0,
		testutil.ToFloat64(m.filterDecisions.WithLabelValues("route-a", "b", "Gibberish", "reject")),
		"unknown scope dispatch must still emit a decision counter")
}

// TestDispatcher_NilMetricsDoesNotPanic proves the existing
// metric-less construction path is unchanged — the *PrometheusMetrics
// field is optional.
func TestDispatcher_NilMetricsDoesNotPanic(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	require.NoError(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	require.NotPanics(t, func() {
		_ = d.Dispatch(context.Background(), &FilterRequest{
			Route: "route-a", Backend: "b",
			Scope: ScopeRequest, Headers: NewHeaderView(nil),
		}, []byte(`{}`))
	})
}
