// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// Tests for L04: X-Content-Filter-Status header on every proxied response.
//
// The header is the single observable handle dashboards and integration
// tests use to correlate filter outcomes with specific requests without
// parsing the response body. It must be accurate on EVERY exit path of
// applyContentFilterOn{Request,Response} regardless of failure policy,
// and the matching mcp_filter_status_total counter must be emitted
// exactly once per non-off status.
//
// After the gateway slimming refactor, the filter is exclusively
// invoked over HTTP against an external service. These tests stand up
// a httptest.NewServer that returns canned filter verdicts to exercise
// every status branch without an in-process dispatcher.

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

// passFilterServer returns an httptest server that always responds
// with a pass verdict.
func passFilterServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
}

// redactFilterServer returns an httptest server that responds with a
// redact verdict whose replacement body is the supplied bytes.
func redactFilterServer(t *testing.T, replacement []byte, reason string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action:     contentFilterActionRedact,
			BodyBase64: base64.StdEncoding.EncodeToString(replacement),
			Reason:     reason,
		})
	}))
}

// rejectFilterServer returns an httptest server that always responds
// with a reject verdict.
func rejectFilterServer(t *testing.T, reason string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action: contentFilterActionReject,
			Reason: reason,
		})
	}))
}

// brokenFilterServer returns an httptest server that always responds
// with malformed JSON, forcing the gateway's fail-open / fail-closed
// branch.
func brokenFilterServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
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
	srv := passFilterServer(t)
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
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
	redacted := &jsonrpc.Request{
		ID:     makeID(t, float64(999)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup", "redacted": true}),
	}
	redactedBody, encErr := jsonrpc.EncodeMessage(redacted)
	require.NoError(t, encErr)

	srv := redactFilterServer(t, redactedBody, "pii removed")
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)

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
	require.Equal(t, req.ID, got.ID, "redact must preserve the original JSON-RPC ID")
}

func TestApplyContentFilterOnRequestWithStatus_RejectReportsReject(t *testing.T) {
	srv := rejectFilterServer(t, "blocked by policy")
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
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
	srv := brokenFilterServer(t)
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, true) // fail-closed

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
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
	srv := brokenFilterServer(t)
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false) // fail-open

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
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
	srv := passFilterServer(t)
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)

	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, status, err := applyContentFilterOnResponseWithStatus(
		context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, FilterStatusPass, status)
}

func TestApplyContentFilterOnResponseWithStatus_RejectReportsReject(t *testing.T) {
	srv := rejectFilterServer(t, "blocked by policy")
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)

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
	rec := httptest.NewRecorder()
	writeFilterStatus(rec, "r1", "b1", FilterStatusPass)
	writeFilterStatus(rec, "r1", "b1", FilterStatusRedact)
	require.Equal(t, "redact", rec.Header().Get(filterStatusHeader))
}

func TestWriteFilterStatus_NilWriterIsNoop(t *testing.T) {
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
	writeFilterStatus(nil, "r", "b", FilterStatusPass)
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

	srv := passFilterServer(t)
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)

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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = proxy.proxyResponseBody(
		ctx, s, rr, httpResp,
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
