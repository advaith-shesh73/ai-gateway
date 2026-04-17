// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Test helpers shared by the per-backend parity tests.
//
// We deliberately build small, purpose-specific fakes here rather than
// reusing internal/testing/fakepii because:
//
//   - The Python backend tests use a trivial replace-map PII fake (not
//     the regex-based NER mock). Mirroring that shape keeps test code
//     parity-aligned.
//
//   - Concurrency tests want to observe peak-in-flight counts, so the
//     fake needs an instrumentation hook that fakepii does not expose.
//
//   - Some tests want the PII service to raise a PIIServiceError
//     without spinning up a full HTTP round-trip; the anonymizer-func
//     pattern lets us do that inline.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// quietBackendLogger is a test-wide logger that discards output, since
// the handlers intentionally emit warn lines on PII / Jira failure.
func quietBackendLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// replaceMapPIIFakeServer stands up a tiny httptest.Server that
// implements the /anonymize contract the real PIIClient expects, and
// performs literal string-replace over incoming text using a
// caller-supplied replace map. This matches the Python FakePIIClient's
// behavior one-for-one.
//
// It also records every (text, context) pair it saw for assertion, and
// maintains in-flight / peak counters so parallelism tests can assert
// the handler correctly bounds fan-out.
type replaceMapPIIFakeServer struct {
	server   *httptest.Server
	replace  map[string]string
	delay    time.Duration
	failErr  error  // if non-nil, every /anonymize returns 500
	failText string // if non-empty, /anonymize returns 500 when text contains this substring

	mu       sync.Mutex
	calls    []pIITextCall
	inFlight int64
	peak     int64
}

// pIITextCall captures a single /anonymize invocation.
type pIITextCall struct {
	Text    string
	Context string
}

// newReplaceMapPIIFakeServer boots a fake PII HTTP server. The caller
// must Close() it in a t.Cleanup.
func newReplaceMapPIIFakeServer(t *testing.T, replace map[string]string) *replaceMapPIIFakeServer {
	t.Helper()
	f := &replaceMapPIIFakeServer{replace: replace}
	mux := http.NewServeMux()
	mux.HandleFunc("/anonymize", f.handleAnonymize)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

// WithDelay is a chainable setter that injects per-call sleep. Used by
// parallelism tests to observe peak concurrency.
func (f *replaceMapPIIFakeServer) WithDelay(d time.Duration) *replaceMapPIIFakeServer {
	f.delay = d
	return f
}

// WithFailure is a chainable setter that makes every call return 500.
// Used to exercise fail-closed paths.
func (f *replaceMapPIIFakeServer) WithFailure(err error) *replaceMapPIIFakeServer {
	f.failErr = err
	return f
}

// WithFailOnText is a chainable setter that makes /anonymize return
// 500 when the incoming text contains the substring. Used to exercise
// partial-failure abort behavior.
func (f *replaceMapPIIFakeServer) WithFailOnText(substring string) *replaceMapPIIFakeServer {
	f.failText = substring
	return f
}

// URL returns the /anonymize endpoint URL suitable for PIIClientConfig.
func (f *replaceMapPIIFakeServer) URL() string {
	return f.server.URL + "/anonymize"
}

// Calls returns a copy of the call log. Safe to call concurrently.
func (f *replaceMapPIIFakeServer) Calls() []pIITextCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]pIITextCall, len(f.calls))
	copy(out, f.calls)
	return out
}

// PeakConcurrency returns the largest observed number of simultaneous
// in-flight /anonymize calls.
func (f *replaceMapPIIFakeServer) PeakConcurrency() int64 {
	return atomic.LoadInt64(&f.peak)
}

// handleAnonymize applies the replace map and returns the anonymized
// text, or 500 when configured to fail.
func (f *replaceMapPIIFakeServer) handleAnonymize(w http.ResponseWriter, r *http.Request) {
	inFlight := atomic.AddInt64(&f.inFlight, 1)
	// Update peak using a CAS-ish loop so concurrent callers agree.
	for {
		p := atomic.LoadInt64(&f.peak)
		if inFlight <= p || atomic.CompareAndSwapInt64(&f.peak, p, inFlight) {
			break
		}
	}
	defer atomic.AddInt64(&f.inFlight, -1)

	if f.delay > 0 {
		time.Sleep(f.delay)
	}

	var req struct {
		Text    string `json:"text"`
		Context string `json:"context"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	f.mu.Lock()
	f.calls = append(f.calls, pIITextCall{Text: req.Text, Context: req.Context})
	f.mu.Unlock()

	if f.failErr != nil {
		http.Error(w, f.failErr.Error(), http.StatusInternalServerError)
		return
	}
	if f.failText != "" && strings.Contains(req.Text, f.failText) {
		http.Error(w, "simulated failure", http.StatusInternalServerError)
		return
	}

	out := req.Text
	for needle, replacement := range f.replace {
		out = strings.ReplaceAll(out, needle, replacement)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"text": out})
}

// newPIIClientForBackend builds a PIIClient pointed at a fake PII server
// with test-friendly defaults. The resulting client can be shared across
// multiple handler calls.
func newPIIClientForBackend(t *testing.T, serverURL string) *PIIClient {
	t.Helper()
	c, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
		URL:               serverURL,
		Timeout:           5 * time.Second,
		FailClosed:        true,
		MaxChars:          40000,
		MaxParallelChunks: 4,
		Logger:            quietBackendLogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}
	return c
}

// newPIIClientForBackendWithObserver is like newPIIClientForBackend but
// attaches a PIIMetrics observer so tests can assert on context labels
// (the PII wire protocol does not carry context; it's a local label only).
func newPIIClientForBackendWithObserver(t *testing.T, serverURL string, obs PIIMetrics) *PIIClient {
	t.Helper()
	c, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
		URL:               serverURL,
		Timeout:           5 * time.Second,
		FailClosed:        true,
		MaxChars:          40000,
		MaxParallelChunks: 4,
		Logger:            quietBackendLogger(),
		Observer:          obs,
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}
	return c
}

// contextRecordingPIIMetrics captures every piiContext label seen on
// RecordCall, AddBytes, and ObserveCallDuration so tests can assert on
// the handler's labeling without depending on wire-level details.
type contextRecordingPIIMetrics struct {
	mu       sync.Mutex
	contexts []string // one entry per RecordCall with the context label
	bytes    map[string]int64
}

func newContextRecordingPIIMetrics() *contextRecordingPIIMetrics {
	return &contextRecordingPIIMetrics{bytes: map[string]int64{}}
}

// Contexts returns a snapshot of every RecordCall context seen, in the
// order they were recorded.
func (m *contextRecordingPIIMetrics) Contexts() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.contexts))
	copy(out, m.contexts)
	return out
}

func (m *contextRecordingPIIMetrics) RecordCall(_, piiContext string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.contexts = append(m.contexts, piiContext)
}
func (m *contextRecordingPIIMetrics) ObserveCallDuration(time.Duration, string) {}
func (m *contextRecordingPIIMetrics) ObserveChunkFanout(int, string)            {}
func (m *contextRecordingPIIMetrics) AddBytes(n int64, ctx string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bytes[ctx] += n
}
func (m *contextRecordingPIIMetrics) RecordCacheLookup(string, string) {}

// makeBackendRequest is a small convenience that mirrors the Python
// `make_request` helper: accepts the scope, backend, tool, and header
// map, and builds a FilterRequest with a prepared HeaderView. Returns
// a pointer so callers can pass directly to Dispatch / handlers without
// copying the 96-byte struct on every invocation.
func makeBackendRequest(scope Scope, backend, tool string, headers map[string]string) *FilterRequest {
	raw := make(map[string][]string, len(headers))
	for k, v := range headers {
		raw[k] = []string{v}
	}
	return &FilterRequest{
		Route:     "test-route",
		Backend:   backend,
		Scope:     scope,
		MCPMethod: "tools/call",
		Tool:      tool,
		Headers:   NewHeaderView(raw),
	}
}

// makeMCPRequestBody builds a minimal JSON-RPC request body matching
// Python's `make_mcp_request_body`.
func makeMCPRequestBody(tool string, arguments map[string]any) map[string]any {
	if arguments == nil {
		arguments = map[string]any{}
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": arguments,
		},
	}
}

// makeMCPResponseBody builds a minimal JSON-RPC response body matching
// Python's `make_mcp_response_body` with one text part per string.
func makeMCPResponseBody(texts []string) map[string]any {
	content := make([]any, 0, len(texts))
	for _, t := range texts {
		content = append(content, map[string]any{"type": "text", "text": t})
	}
	return map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": content,
		},
	}
}

// decodeBackendBody parses a redact body back into a map for assertions.
// Mirrors Python's decode_body helper.
func decodeBackendBody(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return out
}

// backendTextParts returns the content-text strings from a redact body.
func backendTextParts(body map[string]any) []string {
	result, ok := body["result"].(map[string]any)
	if !ok {
		return nil
	}
	content, ok := result["content"].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(content))
	for _, c := range content {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := cm["type"].(string); t != "text" {
			continue
		}
		s, _ := cm["text"].(string)
		out = append(out, s)
	}
	return out
}

// makeHandlerDeps builds a HandlerContext with a default-valid policy,
// the given PII client (nil allowed), and an optional Jira client.
func makeHandlerDeps(pii *PIIClient, jira *JiraClient) HandlerContext {
	p := filterapi.DefaultMCPContentFilterPolicy()
	return HandlerContext{
		Policy: &p,
		PII:    pii,
		Jira:   jira,
		Logger: quietBackendLogger(),
	}
}

// makeHandlerDepsWithEvalHeader is like makeHandlerDeps but lets the
// caller set a custom eval header name / strict flag.
func makeHandlerDepsWithEvalHeader(pii *PIIClient, jira *JiraClient, headerName string, strict bool) HandlerContext {
	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Eval.Name = headerName
	p.Eval.Strict = strict
	return HandlerContext{
		Policy: &p,
		PII:    pii,
		Jira:   jira,
		Logger: quietBackendLogger(),
	}
}

// newJiraTestBackendServer spins up a small httptest.Server that serves
// a single fixed issue response at GET /rest/api/3/issue/{key}. Used by
// the Jira handler's T0 reconstruction tests.
func newJiraTestBackendServer(t *testing.T, key string, issueJSON map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	// The real JiraClient uses /rest/api/3/issue/{key}?expand=changelog.
	mux.HandleFunc("/rest/api/3/issue/"+key, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issueJSON)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newJiraClientForBackend builds a JiraClient pointed at the given
// baseURL with test-friendly defaults.
func newJiraClientForBackend(t *testing.T, baseURL string) *JiraClient {
	t.Helper()
	c, err := NewJiraClient(&JiraClientConfig{
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		BaseURL:    baseURL,
		Email:      "bot@example.com",
		APIToken:   "token123",
		Timeout:    5 * time.Second,
		Logger:     quietBackendLogger(),
	})
	if err != nil {
		t.Fatalf("NewJiraClient: %v", err)
	}
	return c
}

// makeArgumentsHeader builds the x-aigwcf-request-arguments JSON value
// used by the Jira handler's get-issue response flow.
func makeArgumentsHeader(t *testing.T, toolName string, arguments map[string]any) string {
	t.Helper()
	payload := map[string]any{
		"params": map[string]any{
			"name":      toolName,
			"arguments": arguments,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal arguments header: %v", err)
	}
	return string(b)
}

// ctxTODO returns a short-deadline context so stuck tests fail fast.
func ctxTODO() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// alwaysFailServer is a tiny HTTP server that responds 500 to every
// request. Used by tests that need to drive a backend client into an
// error path without depending on the specific URL shape of that client.
type alwaysFailServer struct {
	srv *httptest.Server
}

// URL returns the server's base URL (e.g. "http://127.0.0.1:XXXX").
func (s *alwaysFailServer) URL() string { return s.srv.URL }

func startAlwaysFailServer(t *testing.T) *alwaysFailServer {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "simulated failure", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return &alwaysFailServer{srv: srv}
}
