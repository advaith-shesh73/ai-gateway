// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Dispatcher parity tests. One-to-one with
// aigw-content-filter/tests/test_filter_core.py so a grep across the
// Python and Go suites matches on test name.

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// -----------------------------------------------------------------------
// BuildDispatcher construction parity
// -----------------------------------------------------------------------

func TestBuildDispatcher_EnablesAllHandlersByDefault(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.EnableJira = true
	p.Jira.BaseURL = "https://jira.example.com"
	p.Jira.Email = "svc@example.com"
	p.Jira.APITokenFromEnv = "JIRA_TOKEN"
	requireNoErr(t, p.Validate())

	fake := newReplaceMapPIIFakeServer(t, nil)
	pii := newPIIClientForBackend(t, fake.URL())
	d := BuildDispatcher(&p, pii, nil, nil)

	handlers := d.Handlers()
	if _, ok := handlers["supportgpt"].(*SupportGPTHandler); !ok {
		t.Fatalf("supportgpt: got %T", handlers["supportgpt"])
	}
	if _, ok := handlers["nurag"].(*NuRAGHandler); !ok {
		t.Fatalf("nurag: got %T", handlers["nurag"])
	}
	if _, ok := handlers["glean"].(*GleanHandler); !ok {
		t.Fatalf("glean: got %T", handlers["glean"])
	}
	if _, ok := handlers["jira"].(*JiraHandler); !ok {
		t.Fatalf("jira: got %T", handlers["jira"])
	}
	if _, ok := handlers["atlassian"].(*JiraHandler); !ok {
		t.Fatalf("atlassian: got %T", handlers["atlassian"])
	}
	if _, ok := d.DefaultHandlerInstance().(*DefaultHandler); !ok {
		t.Fatalf("default: got %T", d.DefaultHandlerInstance())
	}
}

func TestBuildDispatcher_HandlerNamesRegisteredLowercase(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.SupportGPTBackendNames = []string{"SUPPORTGPT"}
	requireNoErr(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	if _, ok := d.Handlers()["supportgpt"]; !ok {
		t.Fatalf("expected 'supportgpt' key, got %v", d.Handlers())
	}
	if _, ok := d.Handlers()["SUPPORTGPT"]; ok {
		t.Fatalf("did not expect 'SUPPORTGPT' uppercase key")
	}
}

func TestBuildDispatcher_DisabledHandlersAbsent(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.EnableSupportGPT = false
	p.Backends.EnableNuRAG = false
	p.Backends.EnableGlean = false
	p.Backends.EnableJira = false
	requireNoErr(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	if got := len(d.Handlers()); got != 0 {
		t.Fatalf("expected empty handlers map, got %d entries", got)
	}
	if _, ok := d.DefaultHandlerInstance().(*DefaultHandler); !ok {
		t.Fatalf("default handler missing or wrong type: %T", d.DefaultHandlerInstance())
	}
}

func TestBuildDispatcher_DefaultPIIScanSetIsLowercased(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.PIIScanBackends = []string{"MyBackend", "OTHER", "Already_Lower"}
	requireNoErr(t, p.Validate())

	// Provide a PII fake that replaces "secret" with a sentinel so we
	// can distinguish "scan ran" (redact) from "backend not in set" (pass).
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"secret": "<S>"})
	pii := newPIIClientForBackend(t, fake.URL())

	d := BuildDispatcher(&p, pii, nil, nil)
	dh, ok := d.DefaultHandlerInstance().(*DefaultHandler)
	if !ok {
		t.Fatalf("default is not *DefaultHandler: %T", d.DefaultHandlerInstance())
	}

	ctx, cancel := ctxTODO()
	defer cancel()
	// Call with UPPERCASE backend name; if lowercasing worked it
	// should match "MyBackend" lowercased and the scan runs.
	req := makeBackendRequest(ScopeResponse, "MYBACKEND", "x", nil)
	body := makeMCPResponseBody([]string{"has secret here"})
	resp := dh.HandleResponse(ctx, req, body, HandlerContext{
		Policy: &p,
		PII:    pii,
		Logger: discardSlogLogger(),
	})
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact (scan ran on uppercase 'MYBACKEND'), got %s (reason=%s)",
			resp.Action, resp.Reason)
	}
}

// discardSlogLogger returns a no-op slog logger suitable for tests that
// do not care about log output.
func discardSlogLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discardWriter{}, nil))
}

func TestBuildDispatcher_AliasesShareHandlerInstance(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.EnableJira = true
	p.Backends.JiraBackendNames = []string{"atlassian", "jira", "jira-cloud"}
	p.Jira.BaseURL = "https://jira.example.com"
	p.Jira.Email = "svc@example.com"
	p.Jira.APITokenFromEnv = "JIRA_TOKEN"
	requireNoErr(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)
	hs := d.Handlers()
	if hs["atlassian"] != hs["jira"] {
		t.Fatalf("atlassian and jira must share the same handler instance")
	}
	if hs["jira"] != hs["jira-cloud"] {
		t.Fatalf("jira and jira-cloud must share the same handler instance")
	}
}

// -----------------------------------------------------------------------
// Dispatch routing parity
// -----------------------------------------------------------------------

func TestDispatch_RoutesToSupportGPT(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	body := makeMCPRequestBody("search_cases", nil)
	req := makeBackendRequest(ScopeRequest, "supportgpt", "search_cases",
		map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
	resp := d.Dispatch(ctx, req, body)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (reason=%s)", resp.Action, resp.Reason)
	}
}

func TestDispatch_RoutesToNuRAG(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	body := makeMCPRequestBody("query_knowledge", nil)
	req := makeBackendRequest(ScopeRequest, "nurag", "query_knowledge",
		map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
	resp := d.Dispatch(ctx, req, body)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (reason=%s)", resp.Action, resp.Reason)
	}
}

func TestDispatch_RoutesToGlean(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	body := makeMCPRequestBody("search", map[string]any{"query": "x"})
	req := makeBackendRequest(ScopeRequest, "glean", "search",
		map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
	resp := d.Dispatch(ctx, req, body)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (reason=%s)", resp.Action, resp.Reason)
	}
}

func TestDispatch_RoutesToJiraForBothAliases(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.EnableJira = true
	p.Jira.BaseURL = "https://jira.example.com"
	p.Jira.Email = "svc@example.com"
	p.Jira.APITokenFromEnv = "JIRA_TOKEN"
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	for _, backend := range []string{"jira", "atlassian"} {
		body := makeMCPRequestBody("searchJiraIssuesUsingJql",
			map[string]any{"jql": "project = ENG"})
		req := makeBackendRequest(ScopeRequest, backend, "searchJiraIssuesUsingJql",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
		resp := d.Dispatch(ctx, req, body)
		if resp.Action != ActionRedact {
			t.Fatalf("backend=%s: expected redact, got %s (reason=%s)", backend, resp.Action, resp.Reason)
		}
	}
}

func TestDispatch_UnknownBackendFallsBackToDefault(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	body := makeMCPResponseBody([]string{"John"})
	req := makeBackendRequest(ScopeResponse, "unknown_backend", "x", nil)
	resp := d.Dispatch(ctx, req, body)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass (backend not in scan set), got %s (reason=%s)",
			resp.Action, resp.Reason)
	}
}

func TestDispatch_UnknownScopeRejected(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	req := makeBackendRequest("Weird", "supportgpt", "tool", nil)
	resp := d.Dispatch(ctx, req, nil)
	if resp.Action != ActionReject {
		t.Fatalf("expected reject, got %s", resp.Action)
	}
	if resp.Code != CodeInvalidRequest {
		t.Fatalf("expected code %d, got %d", CodeInvalidRequest, resp.Code)
	}
}

func TestDispatch_BackendMatchingIsCaseInsensitive(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	body := makeMCPRequestBody("search_cases", nil)
	req := makeBackendRequest(ScopeRequest, "SUPPORTGPT", "search_cases",
		map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
	resp := d.Dispatch(ctx, req, body)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (reason=%s)", resp.Action, resp.Reason)
	}
}

// -----------------------------------------------------------------------
// Dispatcher structural contracts: nil safety, snapshot isolation, etc.
// -----------------------------------------------------------------------

func TestBuildDispatcher_NilLoggerIsSafe(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())

	d := BuildDispatcher(&p, nil, nil, nil)

	ctx, cancel := ctxTODO()
	defer cancel()
	req := makeBackendRequest(ScopeResponse, "unknown", "", nil)
	resp := d.Dispatch(ctx, req, nil)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestDispatcher_HandlersSnapshotIsCopy(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	snap := d.Handlers()
	delete(snap, "supportgpt")
	if _, ok := d.Handlers()["supportgpt"]; !ok {
		t.Fatalf("dispatcher's private handler table was mutated by caller")
	}
}

func TestDispatcher_PolicyAccessor(t *testing.T) {
	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)
	if d.Policy() != &p {
		t.Fatalf("Policy() must return the same pointer that was passed to BuildDispatcher")
	}
}

// -----------------------------------------------------------------------
// Concurrency safety: dispatching many requests in parallel must not
// tear the handler table or accumulate shared state across dispatches.
// -----------------------------------------------------------------------

func TestDispatcher_ParallelDispatchStable(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())
	d := BuildDispatcher(&p, nil, nil, nil)

	var calls atomic.Int64
	const workers = 16
	const perWorker = 32
	done := make(chan struct{}, workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer func() { done <- struct{}{} }()
			for i := 0; i < perWorker; i++ {
				var scope Scope
				if i%2 == 0 {
					scope = ScopeRequest
				} else {
					scope = ScopeResponse
				}
				var backend, tool string
				switch (w + i) % 4 {
				case 0:
					backend = "supportgpt"
					tool = "search_cases"
				case 1:
					backend = "nurag"
					tool = "query_knowledge"
				case 2:
					backend = "glean"
					tool = "search"
				default:
					backend = "weird_backend"
					tool = ""
				}
				body := makeMCPRequestBody(tool, nil)
				if scope == ScopeResponse {
					body = makeMCPResponseBody([]string{"hello"})
				}
				req := makeBackendRequest(scope, backend, tool,
					map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
				resp := d.Dispatch(ctx, req, body)
				if resp.Action == "" {
					t.Errorf("empty action on dispatch %d:%d", w, i)
				}
				calls.Add(1)
			}
		}(w)
	}
	for i := 0; i < workers; i++ {
		<-done
	}
	if got, want := calls.Load(), int64(workers*perWorker); got != want {
		t.Fatalf("expected %d dispatches, got %d", want, got)
	}
}

// -----------------------------------------------------------------------
// Cross-dispatch contract: HandlerContext.Policy/PII/Jira/Logger match
// what was passed into BuildDispatcher.
// -----------------------------------------------------------------------

func TestDispatcher_DepsPlumbedToHandlers(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	p.Backends.EnableJira = true
	p.Jira.BaseURL = "https://jira.example.com"
	p.Jira.Email = "svc@example.com"
	p.Jira.APITokenFromEnv = "JIRA_TOKEN"
	requireNoErr(t, p.Validate())

	fake := newReplaceMapPIIFakeServer(t, nil)
	pii := newPIIClientForBackend(t, fake.URL())

	jiraSrv := newJiraTestBackendServer(t, "ENG-1", nil)
	jira := newJiraClientForBackend(t, jiraSrv.URL)

	d := BuildDispatcher(&p, pii, jira, nil)

	probe := &probeHandler{}
	d.handlers["__probe__"] = probe

	req := makeBackendRequest(ScopeRequest, "__probe__", "tool", nil)
	_ = d.Dispatch(ctx, req, makeMCPRequestBody("tool", nil))

	if probe.seen.Policy != &p {
		t.Fatalf("Policy pointer not plumbed through: got %p want %p",
			probe.seen.Policy, &p)
	}
	if probe.seen.PII != pii {
		t.Fatalf("PII pointer not plumbed through")
	}
	if probe.seen.Jira != jira {
		t.Fatalf("Jira pointer not plumbed through")
	}
	if probe.seen.Logger == nil {
		t.Fatalf("Logger must never be nil in HandlerContext")
	}
}

// probeHandler captures the HandlerContext it receives on HandleRequest
// so the dispatcher test can assert on dependency plumbing.
type probeHandler struct {
	BaseHandler
	seen HandlerContext
}

func (h *probeHandler) Name() string { return "__probe__" }

func (h *probeHandler) HandleRequest(_ context.Context, _ *FilterRequest, _ any, deps HandlerContext) FilterResponse {
	h.seen = deps
	return PassResponse("probe-pass")
}

func (h *probeHandler) HandleResponse(_ context.Context, _ *FilterRequest, _ any, _ HandlerContext) FilterResponse {
	return PassResponse("probe-pass")
}

// -----------------------------------------------------------------------
// Log emission: the dispatcher must emit a structured log line with
// expected fields.
// -----------------------------------------------------------------------

func TestDispatcher_EmitsStructuredLogLine(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	p := filterapi.DefaultMCPContentFilterPolicy()
	requireNoErr(t, p.Validate())

	capture := newCapturingSlogHandler()
	logger := slog.New(capture)

	d := BuildDispatcher(&p, nil, nil, logger)

	req := makeBackendRequest(ScopeRequest, "supportgpt", "search_cases",
		map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
	_ = d.Dispatch(ctx, req, makeMCPRequestBody("search_cases", nil))

	found := false
	for _, rec := range capture.Records() {
		if rec.Message != "dispatch" {
			continue
		}
		attrs := map[string]string{}
		rec.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.String()
			return true
		})
		for _, required := range []string{"route", "backend", "backendLower", "scope", "handler", "action"} {
			if _, ok := attrs[required]; !ok {
				t.Errorf("missing required attr %q on dispatch log line; attrs=%v", required, attrs)
			}
		}
		if attrs["backend"] != "supportgpt" {
			t.Errorf("backend attr = %q, want supportgpt", attrs["backend"])
		}
		if attrs["handler"] != "supportgpt" {
			t.Errorf("handler attr = %q, want supportgpt", attrs["handler"])
		}
		if !strings.EqualFold(attrs["scope"], "Request") {
			t.Errorf("scope attr = %q, want Request", attrs["scope"])
		}
		found = true
	}
	if !found {
		t.Fatalf("expected at least one 'dispatch' log record, got %d total records",
			len(capture.Records()))
	}
}

// -----------------------------------------------------------------------
// Tiny helpers private to this test file
// -----------------------------------------------------------------------

// requireNoErr fails the test if err != nil.
func requireNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// capturingSlogHandler is a minimal slog.Handler that records every
// Record it sees so tests can assert on emitted fields.
type capturingSlogHandler struct {
	mu      sync.Mutex
	records []slog.Record
	attrs   []slog.Attr
	groups  []string
}

func newCapturingSlogHandler() *capturingSlogHandler {
	return &capturingSlogHandler{}
}

func (h *capturingSlogHandler) Records() []slog.Record {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]slog.Record, len(h.records))
	copy(out, h.records)
	return out
}

func (h *capturingSlogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

// Handle satisfies slog.Handler; slog.Record is by-value per interface
// contract, so we can't pass it by pointer.
//
//nolint:gocritic // slog.Handler.Handle signature mandates pass-by-value Record
func (h *capturingSlogHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r)
	return nil
}

func (h *capturingSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	// Share the same records slice via the original handler pointer so
	// a single test sees every log line even after WithAttrs chaining.
	return &childCapturingSlogHandler{
		parent: h,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: h.groups,
	}
}

func (h *capturingSlogHandler) WithGroup(name string) slog.Handler {
	return &childCapturingSlogHandler{
		parent: h,
		attrs:  h.attrs,
		groups: append(append([]string{}, h.groups...), name),
	}
}

// childCapturingSlogHandler forwards every Handle call to the parent so
// the parent's `records` slice remains the single source of truth.
type childCapturingSlogHandler struct {
	parent *capturingSlogHandler
	attrs  []slog.Attr
	groups []string
}

func (h *childCapturingSlogHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return h.parent.Enabled(ctx, l)
}

// Handle satisfies slog.Handler; slog.Record is by-value per interface
// contract, so we can't pass it by pointer.
//
//nolint:gocritic // slog.Handler.Handle signature mandates pass-by-value Record
func (h *childCapturingSlogHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.parent.Handle(ctx, r)
}

func (h *childCapturingSlogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &childCapturingSlogHandler{
		parent: h.parent,
		attrs:  append(append([]slog.Attr{}, h.attrs...), attrs...),
		groups: h.groups,
	}
}

func (h *childCapturingSlogHandler) WithGroup(name string) slog.Handler {
	return &childCapturingSlogHandler{
		parent: h.parent,
		attrs:  h.attrs,
		groups: append(append([]string{}, h.groups...), name),
	}
}
