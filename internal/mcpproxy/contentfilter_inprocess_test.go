// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// Tests for PR D.1 wire-up: `WithDispatcher` mutation on the existing
// contentFilter struct, and the branch inside applyContentFilterOn*
// that prefers the dispatcher over the HTTP sidecar when one is attached.
//
// Invariants verified:
//
//  1. Zero-touch HTTP fallback: a contentFilter with dispatcher==nil
//     behaves EXACTLY as today (regression guard for Python-era behavior).
//  2. Dispatcher preference: when WithDispatcher(d) is set, HTTP is NEVER
//     consulted — no network traffic escapes the process.
//  3. Pass / Redact / Reject fidelity on both Request and Response scope.
//  4. Fail-closed and fail-open paths fire correctly on dispatcher errors
//     (via a handler that panics / returns unknown action).
//  5. JSON-RPC ID is preserved through dispatcher redacts (same contract
//     as HTTP path).
//  6. Concurrency: N concurrent callers hitting the same (cf, dispatcher)
//     pair all succeed under -race.
//
// Style: the tests mirror existing contentfilter_test.go (testify/require,
// httptest-backed servers where needed, table-driven when value adds).

// fakeHandler is a single-purpose Handler for wire-up tests. It avoids
// pulling in a full dispatcher-with-backends; we only need to verify
// that dispatchInProcess correctly plumbs input→output.
//
// The handler routes BOTH HandleRequest and HandleResponse through a
// single `fn` so tests can be terse. Tests that need different verdicts
// per scope can branch on `req.Scope` inside `fn`.
type fakeHandler struct {
	name string
	// fn returns the FilterResponse for a given (req, body) pair.
	// Defaults to PassResponse() if nil.
	fn func(ctx context.Context, req *FilterRequest, body any) FilterResponse
	// calls counts invocations for concurrency / preference tests.
	calls atomic.Int64
	// lastScope, lastBackend capture the last invocation for ordering
	// assertions (guarded by mu for -race cleanliness).
	mu          sync.Mutex
	lastScope   Scope
	lastBackend string
}

func (h *fakeHandler) Name() string { return h.name }

func (h *fakeHandler) HandleRequest(ctx context.Context, req *FilterRequest, body any, _ HandlerContext) FilterResponse {
	return h.handle(ctx, req, body)
}

func (h *fakeHandler) HandleResponse(ctx context.Context, req *FilterRequest, body any, _ HandlerContext) FilterResponse {
	return h.handle(ctx, req, body)
}

func (h *fakeHandler) handle(ctx context.Context, req *FilterRequest, body any) FilterResponse {
	h.calls.Add(1)
	h.mu.Lock()
	h.lastScope = req.Scope
	h.lastBackend = req.Backend
	h.mu.Unlock()
	if h.fn == nil {
		return PassResponse("fake: default pass")
	}
	return h.fn(ctx, req, body)
}

// newDispatcherForHandler builds a minimal dispatcher wrapping a single
// handler — used by every wire-up test in this file. Keeps tests terse
// and bypasses BuildDispatcher's policy-driven handler registration so
// we can isolate the wire-up path from backend-specific logic.
//
// We substitute a discard logger rather than leaving `logger: nil`
// because Dispatch() unconditionally emits one log line per call; a
// nil slog.Logger panics on Info/Warn. BuildDispatcher handles this
// the same way internally.
func newDispatcherForHandler(t *testing.T, h *fakeHandler) *Dispatcher {
	t.Helper()
	p := filterapi.DefaultMCPContentFilterPolicy()
	require.NoError(t, p.Validate(), "default policy must validate")
	return &Dispatcher{
		policy:         &p,
		handlers:       map[string]Handler{strings.ToLower(h.name): h},
		defaultHandler: h,
		logger:         slog.New(slog.NewTextHandler(discardWriter{}, nil)),
	}
}

// newDispatcherFilter builds a contentFilter pointing at the in-process
// dispatcher. URL is a throwaway (never hit); failClosed mirrors the
// existing newTestFilter helper's API so tests read naturally.
func newDispatcherFilter(t *testing.T, d *Dispatcher, failClosed bool) *contentFilter {
	t.Helper()
	// A URL is required by compileContentFilter today (the CRD hasn't
	// dropped it yet), so we give it a clearly-unreachable sentinel
	// that will FAIL LOUDLY if the dispatcher branch is ever bypassed.
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL: "http://dispatcher-should-have-handled-this.invalid.",
		Scopes: []filterapi.MCPContentFilterScope{
			filterapi.MCPContentFilterScopeRequest,
			filterapi.MCPContentFilterScopeResponse,
		},
		TimeoutSeconds: 1,
		FailurePolicy: func() filterapi.MCPContentFilterFailurePolicy {
			if failClosed {
				return filterapi.MCPContentFilterFailurePolicyFail
			}
			return filterapi.MCPContentFilterFailurePolicyPassThrough
		}(),
	}, "r", "b")
	require.NoError(t, err)
	return cf.WithDispatcher(d)
}

// ---------------------------------------------------------------------
// 1. WithDispatcher mutation semantics
// ---------------------------------------------------------------------

func TestWithDispatcher_AttachesAndReturnsSamePointer(t *testing.T) {
	cf := &contentFilter{}
	h := &fakeHandler{name: "fake"}
	d := newDispatcherForHandler(t, h)

	got := cf.WithDispatcher(d)
	require.Same(t, cf, got, "WithDispatcher must return the same pointer for chaining")
	require.Same(t, d, cf.dispatcher, "dispatcher must be attached")
}

func TestWithDispatcher_NilReceiverSafe(t *testing.T) {
	var cf *contentFilter
	got := cf.WithDispatcher(&Dispatcher{})
	require.Nil(t, got, "nil receiver WithDispatcher must return nil, not panic")
}

func TestWithDispatcher_NilDispatcherClearsField(t *testing.T) {
	h := &fakeHandler{name: "fake"}
	d := newDispatcherForHandler(t, h)
	cf := &contentFilter{dispatcher: d}
	cf.WithDispatcher(nil)
	require.Nil(t, cf.dispatcher, "WithDispatcher(nil) must clear the field")
}

// ---------------------------------------------------------------------
// 2. Dispatcher preference — HTTP sidecar is NEVER touched
// ---------------------------------------------------------------------

func TestApplyContentFilterOnRequest_DispatcherPath_PassDoesNotTouchHTTP(t *testing.T) {
	// A tripwire server: every contact FAILS the test. If the wire-up
	// accidentally falls back to HTTP, this server's counter will flip
	// the test red.
	var httpCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpCalls.Add(1)
		http.Error(w, "tripwire: dispatcher was bypassed", http.StatusTeapot)
	}))
	defer srv.Close()

	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return PassResponse("all good")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "pass with unchanged body returns the original *jsonrpc.Request pointer")
	require.Equal(t, int64(0), httpCalls.Load(), "HTTP sidecar MUST NOT be contacted when dispatcher is wired up")
	require.Equal(t, int64(1), h.calls.Load(), "dispatcher handler must be called exactly once")

	h.mu.Lock()
	defer h.mu.Unlock()
	require.Equal(t, ScopeRequest, h.lastScope)
	require.Equal(t, "b", h.lastBackend)
}

func TestApplyContentFilterOnResponse_DispatcherPath_PassDoesNotTouchHTTP(t *testing.T) {
	var httpCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		httpCalls.Add(1)
		http.Error(w, "tripwire", http.StatusTeapot)
	}))
	defer srv.Close()

	h := &fakeHandler{name: "b"}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.NoError(t, err)
	require.Same(t, resp, got)
	require.Equal(t, int64(0), httpCalls.Load())
	require.Equal(t, int64(1), h.calls.Load())

	h.mu.Lock()
	defer h.mu.Unlock()
	require.Equal(t, ScopeResponse, h.lastScope)
}

// ---------------------------------------------------------------------
// 3. Redact fidelity — dispatcher rewrite reaches the caller intact
// ---------------------------------------------------------------------

func TestApplyContentFilterOnRequest_DispatcherPath_RedactReplacesParams(t *testing.T) {
	originalID := makeID(t, float64(99))
	replacement := &jsonrpc.Request{
		ID:     makeID(t, "ignored-by-gateway"),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup", "arguments": map[string]string{"q": "REDACTED"}}),
	}
	repBytes, err := jsonrpc.EncodeMessage(replacement)
	require.NoError(t, err)

	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RedactResponse(repBytes, "scrubbed")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{ID: originalID, Method: "tools/call", Params: mustJSON(t, map[string]any{"name": "lookup"})}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.NotSame(t, req, got, "redact must return a new *jsonrpc.Request")
	require.Equal(t, originalID, got.ID, "gateway preserves original JSON-RPC ID")
	require.Equal(t, "tools/call", got.Method)
	require.Contains(t, string(got.Params), "REDACTED")
}

func TestApplyContentFilterOnResponse_DispatcherPath_RedactReplacesResult(t *testing.T) {
	originalID := makeID(t, float64(42))
	replacement := &jsonrpc.Response{
		ID:     makeID(t, "ignored-by-gateway"),
		Result: mustJSON(t, map[string]any{"data": "[REDACTED]"}),
	}
	repBytes, err := jsonrpc.EncodeMessage(replacement)
	require.NoError(t, err)

	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RedactResponse(repBytes, "scrubbed")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	resp := &jsonrpc.Response{ID: originalID, Result: mustJSON(t, map[string]any{"data": "sensitive-info"})}
	got, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.NoError(t, err)
	require.NotSame(t, resp, got)
	require.Equal(t, originalID, got.ID, "original ID preserved after redact")
	require.Contains(t, string(got.Result), "REDACTED")
}

func TestApplyContentFilterOnRequest_DispatcherPath_RedactEmptyBodyIsPass(t *testing.T) {
	// Parity with HTTP path semantics (redact w/ empty body degrades to pass).
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return FilterResponse{Action: ActionRedact, Body: nil, Reason: "should-be-pass"}
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "empty redact body must degrade to pass")
}

// ---------------------------------------------------------------------
// 4. Reject fidelity — dispatcher reject surfaces errContentFilterRejected
// ---------------------------------------------------------------------

func TestApplyContentFilterOnRequest_DispatcherPath_Reject(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RejectResponse("policy-violation", CodePolicyReject, "")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.ErrorIs(t, err, errContentFilterRejected)
	require.Contains(t, err.Error(), "policy-violation")
}

func TestApplyContentFilterOnResponse_DispatcherPath_Reject(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RejectResponse("pii-unavailable", CodePIIUnavailable, "")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, true) // fail-closed, but reject is an explicit handler verdict

	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	_, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", &jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.ErrorIs(t, err, errContentFilterRejected)
	require.Contains(t, err.Error(), "pii-unavailable")
}

// ---------------------------------------------------------------------
// 5. Dispatcher infrastructure errors respect fail-closed / fail-open
// ---------------------------------------------------------------------

func TestApplyContentFilterOnRequest_DispatcherPath_FailOpenOnUnknownAction(t *testing.T) {
	// A handler returning an unknown action is a programmer error; the
	// dispatchInProcess adapter surfaces it as an infrastructure err.
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return FilterResponse{Action: Action("bogus")}
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false) // fail-open

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "fail-open must return original request unchanged on dispatcher error")
}

func TestApplyContentFilterOnRequest_DispatcherPath_FailClosedOnUnknownAction(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return FilterResponse{Action: Action("bogus")}
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, true) // fail-closed

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.ErrorIs(t, err, errContentFilterFailed)
}

// ---------------------------------------------------------------------
// 6. Invalid replacement body on redact rejects with clear error
// ---------------------------------------------------------------------

func TestApplyContentFilterOnRequest_DispatcherPath_RedactInvalidReplacement(t *testing.T) {
	// Dispatcher returns bytes that are NOT valid JSON-RPC.
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RedactResponse([]byte("{not: valid jsonrpc"), "garbled")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "JSON-RPC")
}

func TestApplyContentFilterOnRequest_DispatcherPath_ReplacementWrongMessageType(t *testing.T) {
	// Replacement is syntactically JSON-RPC but a *response*, not a *request*.
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	respBytes, err := jsonrpc.EncodeMessage(resp)
	require.NoError(t, err)
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return RedactResponse(respBytes, "wrong-type")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err = applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "JSON-RPC request")
}

// ---------------------------------------------------------------------
// 7. Dispatcher sees correct scope / backend / method / tool / headers
// ---------------------------------------------------------------------

func TestDispatcher_ReceivesCorrectFilterRequestFields(t *testing.T) {
	var gotReq FilterRequest
	h := &fakeHandler{name: "b", fn: func(_ context.Context, req *FilterRequest, _ any) FilterResponse {
		gotReq = *req
		return PassResponse("ok")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(7)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup"}),
	}
	headers := http.Header{
		"X-Request-Id":             []string{"abc-123"},
		"X-Eval-Exclude-Ticket-Id": []string{"PROJ-1"},
	}
	_, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		filterapi.MCPRouteName("myroute"), filterapi.MCPBackendName("mybackend"),
		"lookup", req, headers)
	require.NoError(t, err)

	require.Equal(t, "myroute", gotReq.Route)
	require.Equal(t, "mybackend", gotReq.Backend)
	require.Equal(t, ScopeRequest, gotReq.Scope)
	require.Equal(t, "tools/call", gotReq.MCPMethod)
	require.Equal(t, "lookup", gotReq.Tool)
	require.Equal(t, "abc-123", gotReq.Headers.Get("x-request-id"))
	require.Equal(t, "PROJ-1", gotReq.Headers.Get("x-eval-exclude-ticket-id"))
}

func TestDispatcher_ResponseScope_ReceivesMethodFromRequest(t *testing.T) {
	var gotReq FilterRequest
	h := &fakeHandler{name: "b", fn: func(_ context.Context, req *FilterRequest, _ any) FilterResponse {
		gotReq = *req
		return PassResponse("ok")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	// Request carries the method; response is what's being filtered.
	originatingReq := &jsonrpc.Request{Method: "tools/call"}
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	_, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", originatingReq, resp, http.Header{})
	require.NoError(t, err)
	require.Equal(t, ScopeResponse, gotReq.Scope)
	require.Equal(t, "tools/call", gotReq.MCPMethod,
		"response-scope MCPMethod must come from the originating request")
}

func TestDispatcher_ResponseScope_NilRequestEmptyMethod(t *testing.T) {
	// If the originating request pointer is nil, method defaults to "" —
	// same contract as the HTTP path.
	var gotReq FilterRequest
	h := &fakeHandler{name: "b", fn: func(_ context.Context, req *FilterRequest, _ any) FilterResponse {
		gotReq = *req
		return PassResponse("ok")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	_, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", nil, resp, http.Header{})
	require.NoError(t, err)
	require.Empty(t, gotReq.MCPMethod)
}

// ---------------------------------------------------------------------
// 8. HTTP fallback is UNCHANGED when dispatcher is nil
// ---------------------------------------------------------------------

func TestApplyContentFilterOnRequest_HTTPFallback_WhenDispatcherNil(t *testing.T) {
	// Regression guard: a contentFilter constructed WITHOUT a dispatcher
	// must continue to use the HTTP sidecar — this is the zero-touch
	// migration path that rollout relies on.
	var httpCalls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		httpCalls.Add(1)
		require.Equal(t, http.MethodPost, r.Method)
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()

	cf := newTestFilter(t, srv.URL, false)
	require.Nil(t, cf.dispatcher, "sanity: HTTP-only filter has no dispatcher")

	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got)
	require.Equal(t, int64(1), httpCalls.Load(), "HTTP sidecar MUST be contacted when dispatcher is nil")
}

// ---------------------------------------------------------------------
// 9. Concurrency — N parallel callers under -race
// ---------------------------------------------------------------------

func TestDispatcher_ConcurrentCallers_StableUnderRace(t *testing.T) {
	h := &fakeHandler{name: "b", fn: func(_ context.Context, _ *FilterRequest, _ any) FilterResponse {
		return PassResponse("pass")
	}}
	d := newDispatcherForHandler(t, h)
	cf := newDispatcherFilter(t, d, false)

	const workers = 16
	const calls = 32

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < calls; i++ {
				req := &jsonrpc.Request{
					ID:     makeID(t, fmt.Sprintf("w%d-i%d", workerID, i)),
					Method: "tools/call",
					Params: mustJSON(t, map[string]any{"name": "lookup"}),
				}
				_, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
					"r", "b", "lookup", req, http.Header{})
				require.NoError(t, err)
			}
		}(w)
	}
	wg.Wait()

	require.Equal(t, int64(workers*calls), h.calls.Load(),
		"every dispatch must reach the handler (no drops under contention)")
}

// ---------------------------------------------------------------------
// 10. dispatchInProcess direct tests — adapter-level verification
// ---------------------------------------------------------------------

func TestDispatchInProcess_NilDispatcherIsProgrammerError(t *testing.T) {
	_, _, _, err := dispatchInProcess(context.Background(), nil,
		ScopeRequest, "r", "b", "tools/call", "lookup", http.Header{}, []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "programmer error")
}

func TestDispatchInProcess_UndecodableBodyFailsLoud(t *testing.T) {
	h := &fakeHandler{name: "b"}
	d := newDispatcherForHandler(t, h)
	_, _, _, err := dispatchInProcess(context.Background(), d,
		ScopeRequest, "r", "b", "tools/call", "lookup", http.Header{}, []byte(`{not json`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode body")
	require.Equal(t, int64(0), h.calls.Load(), "handler MUST NOT run on decode failure")
}

func TestDispatchInProcess_EmptyBodyIsAllowed(t *testing.T) {
	// An empty body is a legitimate zero-value for scopes that haven't
	// serialized yet; the adapter forwards nil and the handler decides.
	h := &fakeHandler{name: "b"}
	d := newDispatcherForHandler(t, h)
	newBody, rejected, reason, err := dispatchInProcess(context.Background(), d,
		ScopeRequest, "r", "b", "tools/call", "lookup", http.Header{}, nil)
	require.NoError(t, err)
	require.False(t, rejected)
	require.Nil(t, newBody, "empty-in, empty-out (pass)")
	require.Equal(t, "fake: default pass", reason)
}
