// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// Tests for L04: X-Content-Filter-Status header on every proxied response.
//
// The header is the single observable handle dashboards and
// integration tests use to correlate filter outcomes with specific
// requests without parsing the response body. It must be accurate
// on EVERY exit path of applyContentFilterOn{Request,Response}
// regardless of failure policy, and the matching
// mcp_filter_status_total counter must be emitted exactly once per
// non-off status.
//
// This file exercises the contract on both the low-level WithStatus
// helpers (ensuring every code path populates a non-empty status) and
// the package-level writeFilterStatus helper that handlers call.

// statusMetricValue returns the current value of
// mcp_filter_status_total{route,backend,status}. Helper for terse
// assertions across the suite.
func statusMetricValue(t *testing.T, m *PrometheusMetrics, route, backend, status string) float64 {
	t.Helper()
	return testutil.ToFloat64(m.filterStatus.WithLabelValues(route, backend, status))
}

// newStatusTestMetrics constructs a PrometheusMetrics bound to a
// fresh registry so multiple tests in the suite don't interfere. The
// returned *PrometheusMetrics is NOT installed as the package-level
// filterMetrics until the caller does so via SetFilterMetrics.
func newStatusTestMetrics(t *testing.T) *PrometheusMetrics {
	t.Helper()
	return NewPrometheusMetrics(prometheus.NewRegistry())
}

// --- applyContentFilterOnRequestWithStatus: status coverage -------------

func TestApplyContentFilterOnRequestWithStatus_NilFilterIsOff(t *testing.T) {
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, nil,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "nil filter must return the original request pointer")
	require.Equal(t, FilterStatusOff, status, "nil filter status must be off")
}

func TestApplyContentFilterOnRequestWithStatus_ScopeDisabledIsOff(t *testing.T) {
	// A filter that is wired only for Response scope must report
	// FilterStatusOff on the Request path (no silent pass).
	cf := &contentFilter{invokeOnRequest: false, invokeOnResponse: true}
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got)
	require.Equal(t, FilterStatusOff, status)
}

func TestApplyContentFilterOnRequestWithStatus_PassReportsPass(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return PassResponse("clean")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{
		ID: makeID(t, float64(1)), Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}

	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "pass with identical body returns the original pointer")
	require.Equal(t, FilterStatusPass, status)
}

func TestApplyContentFilterOnRequestWithStatus_RedactReportsRedact(t *testing.T) {
	// Pre-encode a replacement body. The wrapper restores the original
	// request's ID post-decode, so the stand-in ID we embed here is
	// irrelevant — only the shape of the body matters.
	redacted := &jsonrpc.Request{
		ID:     makeID(t, float64(999)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup", "redacted": true}),
	}
	redactedBody, encErr := jsonrpc.EncodeMessage(redacted)
	require.NoError(t, encErr)

	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RedactResponse(redactedBody, "pii removed")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(42)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}

	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.NotNil(t, got)
	require.NotSame(t, req, got, "redact returns a new request pointer (body changed)")
	require.Equal(t, FilterStatusRedact, status)
	// ID must be preserved through redact (existing contract).
	require.Equal(t, req.ID, got.ID)
}

func TestApplyContentFilterOnRequestWithStatus_RejectReportsReject(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RejectResponse("blocked by policy", 0, "")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{
		ID: makeID(t, float64(1)), Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}

	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.Nil(t, got, "reject must return nil request")
	require.ErrorIs(t, err, errContentFilterRejected)
	require.Equal(t, FilterStatusReject, status)
}

func TestApplyContentFilterOnRequestWithStatus_FailClosedReportsUnavailable(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		// Return a FilterResponse with an invalid action; the dispatcher
		// adapter translates this into an error.
		return FilterResponse{Action: "bogus"}
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, true) // fail-closed

	req := &jsonrpc.Request{
		ID: makeID(t, float64(1)), Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}

	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.Nil(t, got)
	require.ErrorIs(t, err, errContentFilterFailed)
	require.Equal(t, FilterStatusUnavailable, status)
}

func TestApplyContentFilterOnRequestWithStatus_FailOpenReportsFailedOpen(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return FilterResponse{Action: "bogus"}
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false) // fail-open

	req := &jsonrpc.Request{
		ID: makeID(t, float64(1)), Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}

	got, status, err := applyContentFilterOnRequestWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err, "fail-open must NOT surface an error to the caller")
	require.Same(t, req, got, "fail-open forwards the original request untouched")
	require.Equal(t, FilterStatusFailedOpen, status)
}

// --- applyContentFilterOnResponseWithStatus: status coverage ------------

func TestApplyContentFilterOnResponseWithStatus_NilFilterIsOff(t *testing.T) {
	resp := &jsonrpc.Response{ID: makeID(t, float64(1))}
	got, status, err := applyContentFilterOnResponseWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, nil,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, FilterStatusOff, status)
}

func TestApplyContentFilterOnResponseWithStatus_PassReportsPass(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return PassResponse("clean")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, status, err := applyContentFilterOnResponseWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, FilterStatusPass, status)
}

func TestApplyContentFilterOnResponseWithStatus_RejectReportsReject(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RejectResponse("blocked by policy", 0, "")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, status, err := applyContentFilterOnResponseWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.Nil(t, got)
	require.ErrorIs(t, err, errContentFilterRejected)
	require.Equal(t, FilterStatusReject, status)
}

// --- writeFilterStatus: header + metric emission ------------------------

func TestWriteFilterStatus_SetsHeader(t *testing.T) {
	rec := httptest.NewRecorder()
	writeFilterStatus(rec, "r1", "b1", FilterStatusPass)
	require.Equal(t, "pass", rec.Header().Get(filterStatusHeader))
}

func TestWriteFilterStatus_OverwritesPreviousValue(t *testing.T) {
	// Simulates the Response-scope path overwriting the Request-scope
	// value on the same request — valid by contract because Response
	// scope is authoritative when both fire.
	rec := httptest.NewRecorder()
	writeFilterStatus(rec, "r1", "b1", FilterStatusPass)
	writeFilterStatus(rec, "r1", "b1", FilterStatusRedact)
	require.Equal(t, "redact", rec.Header().Get(filterStatusHeader))
}

func TestWriteFilterStatus_NilWriterIsNoop(t *testing.T) {
	// Tolerating a nil writer keeps the test surface permissive and
	// means we can reuse writeFilterStatus from paths that only care
	// about the metric side-effect.
	require.NotPanics(t, func() {
		writeFilterStatus(nil, "r1", "b1", FilterStatusPass)
	})
}

func TestWriteFilterStatus_EmitsMetricWhenInstalled(t *testing.T) {
	m := newStatusTestMetrics(t)
	t.Cleanup(func() { SetFilterMetrics(nil) })
	SetFilterMetrics(m)

	rec := httptest.NewRecorder()
	writeFilterStatus(rec, "route-x", "backend-y", FilterStatusRedact)

	require.Equal(t, "redact", rec.Header().Get(filterStatusHeader))
	require.Equal(t, 1.0, statusMetricValue(t, m, "route-x", "backend-y", "redact"))
}

func TestWriteFilterStatus_NilMetricsIsSilent(t *testing.T) {
	// Default state: no metrics installed. Header still gets written,
	// no metric side-effect, no panic.
	SetFilterMetrics(nil)
	rec := httptest.NewRecorder()
	require.NotPanics(t, func() {
		writeFilterStatus(rec, "r", "b", FilterStatusPass)
	})
	require.Equal(t, "pass", rec.Header().Get(filterStatusHeader))
}

// --- emitStashedFilterStatus -------------------------------------------

func TestEmitStashedFilterStatus_NilContextIsNoop(t *testing.T) {
	var m *mcpRequestContext
	rec := httptest.NewRecorder()
	require.NotPanics(t, func() { m.emitStashedFilterStatus(rec) })
	require.Empty(t, rec.Header().Get(filterStatusHeader))
}

func TestEmitStashedFilterStatus_UnsetStatusIsNoop(t *testing.T) {
	// Default zero value of FilterStatus is "" (empty string), which
	// signals "no filter fired". The helper must not advertise a
	// header in that case — preserving pre-L04 behavior for backends
	// with no filter configured at all.
	m := &mcpRequestContext{}
	rec := httptest.NewRecorder()
	m.emitStashedFilterStatus(rec)
	require.Empty(t, rec.Header().Get(filterStatusHeader))
}

func TestEmitStashedFilterStatus_WritesHeaderAndMetric(t *testing.T) {
	pm := newStatusTestMetrics(t)
	t.Cleanup(func() { SetFilterMetrics(nil) })
	SetFilterMetrics(pm)

	m := &mcpRequestContext{
		reqScopeFilterStatus:  FilterStatusPass,
		reqScopeFilterRoute:   filterapi.MCPRouteName("route-z"),
		reqScopeFilterBackend: filterapi.MCPBackendName("backend-z"),
	}
	rec := httptest.NewRecorder()
	m.emitStashedFilterStatus(rec)

	require.Equal(t, "pass", rec.Header().Get(filterStatusHeader))
	require.Equal(t, 1.0, statusMetricValue(t, pm, "route-z", "backend-z", "pass"))
}

// --- SetFilterMetrics atomic swap --------------------------------------

func TestSetFilterMetrics_AtomicSwap(t *testing.T) {
	// Swapping metrics under the feet of a handler must not race or
	// panic; the hook is read via atomic.Pointer and every access
	// re-loads.
	a := newStatusTestMetrics(t)
	b := newStatusTestMetrics(t)
	t.Cleanup(func() { SetFilterMetrics(nil) })

	SetFilterMetrics(a)
	writeFilterStatus(nil, "r", "b", FilterStatusPass)
	require.Equal(t, 1.0, statusMetricValue(t, a, "r", "b", "pass"))
	require.Equal(t, 0.0, statusMetricValue(t, b, "r", "b", "pass"))

	SetFilterMetrics(b)
	writeFilterStatus(nil, "r", "b", FilterStatusPass)
	require.Equal(t, 1.0, statusMetricValue(t, a, "r", "b", "pass"), "original metric counter must be untouched")
	require.Equal(t, 1.0, statusMetricValue(t, b, "r", "b", "pass"), "new metric counter must record the post-swap call")

	SetFilterMetrics(nil)
	writeFilterStatus(nil, "r", "b", FilterStatusPass) // no-op on metrics
	require.Equal(t, 1.0, statusMetricValue(t, b, "r", "b", "pass"))
}

// --- End-to-end: proxyResponseBody writes the header on success --------

// TestProxyResponseBody_EmitsFilterStatusHeader drives the full
// `proxyResponseBody` path — which is the primary exit point for
// proxied MCP responses — and asserts that:
//
//  1. X-Content-Filter-Status lands on the ResponseWriter with the
//     authoritative Response-scope outcome (overwriting the
//     Request-scope stash).
//  2. The matching mcp_filter_status_total counter increments for
//     (route, backend, status).
//  3. The response body is forwarded intact (no regression in the
//     happy path — we are only *adding* a header, not altering body
//     semantics).
func TestProxyResponseBody_EmitsFilterStatusHeader(t *testing.T) {
	proxy := newTestMCPProxy()

	pm := newStatusTestMetrics(t)
	t.Cleanup(func() { SetFilterMetrics(nil) })
	SetFilterMetrics(pm)

	const (
		routeName   = filterapi.MCPRouteName("route-a")
		backendName = filterapi.MCPBackendName("backend-a")
	)

	h := &fakeHandler{name: backendName, fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return PassResponse("clean")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	proxy.mcpProxyConfig = &mcpProxyConfig{
		backendListenerAddr: "http://test-backend",
		routes: map[filterapi.MCPRouteName]*mcpProxyConfigRoute{
			routeName: {
				backends:       map[filterapi.MCPBackendName]filterapi.MCPBackend{backendName: {Name: backendName}},
				contentFilters: map[filterapi.MCPBackendName]*contentFilter{backendName: cf},
			},
		},
	}

	id := makeID(t, float64(7))
	resp := &jsonrpc.Response{ID: id, Result: mustJSON(t, map[string]any{"ok": true})}
	body, err := jsonrpc.EncodeMessage(resp)
	require.NoError(t, err)

	httpResp := &http.Response{
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		StatusCode: http.StatusOK,
	}

	rr := httptest.NewRecorder()
	s := &session{route: routeName}
	err = proxy.proxyResponseBody(
		t.Context(), s, rr, httpResp,
		&jsonrpc.Request{Method: "tools/call", ID: id},
		filterapi.MCPBackend{Name: backendName},
	)
	require.NoError(t, err)

	require.Equal(t, "pass", rr.Header().Get(filterStatusHeader),
		"L04: single-JSON proxied response must advertise X-Content-Filter-Status")
	require.InDelta(t, 1.0,
		statusMetricValue(t, pm, routeName, backendName, "pass"),
		0.0001,
		"L04: mcp_filter_status_total must increment in lockstep with the header")
	require.Contains(t, rr.Body.String(), `"ok":true`,
		"proxied body must pass through unchanged when filter verdict is pass")
}
