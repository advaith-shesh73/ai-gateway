// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

//go:build livewire

// Package mcpproxy: livewire tests exercise the in-process Dispatcher
// against a real PII service (GPU-backed /anonymize endpoint). They
// REPLACE the Python-sidecar livewire tests that previously lived in
// contentfilter_live_test.go; that file was deleted in PR D.2 when the
// sidecar path was retired.
//
// These tests are gated by a build tag so a normal `go test` run never
// depends on external processes:
//
//	go test -tags=livewire \
//	  -run 'TestInProcessLivewire' \
//	  ./internal/mcpproxy/... \
//	  -v
//
// Required environment:
//   - PII anonymize service reachable at AIGW_PII_URL
//     (default http://127.0.0.1:8081/anonymize).
//
// Optional environment:
//   - AIGW_LIVEWIRE_EVAL_TICKET: eval ticket to inject in the
//     X-Eval-Exclude-Ticket-Id header (default "ENG-424242").
//
// Why an in-process livewire suite at all?
// ---------------------------------------
// The in-process Dispatcher hides a lot of moving parts (PII client,
// circuit breaker, cache, per-chunk fan-out, Jira T0 replay). Unit
// tests cover each in isolation, but it's easy for a wiring mistake
// to slip past isolated tests and only surface when the real service
// is consulted. This file gives operators a one-button smoke test
// they can run after deploying a new gateway build — the same niche
// the Python-sidecar livewire filled before.
package mcpproxy

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// piiURL returns the configured PII anonymize endpoint or the default.
func piiURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("AIGW_PII_URL")
	if url == "" {
		url = "http://127.0.0.1:8081/anonymize"
	}
	t.Logf("livewire PII url: %s", url)
	return url
}

// livewireEvalTicket returns the eval ticket ID to inject. Callers
// should forward this value in the X-Eval-Exclude-Ticket-Id header.
func livewireEvalTicket() string {
	if v := os.Getenv("AIGW_LIVEWIRE_EVAL_TICKET"); v != "" {
		return v
	}
	return "ENG-424242"
}

// requireLivePIIService probes the configured PII anonymize endpoint
// and skips the calling test if it's not reachable. Tests that only
// exercise in-process handlers (supportgpt, glean, unknown-backend)
// don't need this guard — they never shell out. Tests that exercise
// the default-backend redact path (which posts to the PII service)
// must call this helper first so they skip cleanly when an operator
// runs `-tags=livewire` without the PII service running.
func requireLivePIIService(t *testing.T, url string) {
	t.Helper()
	c := &http.Client{Timeout: 500 * time.Millisecond}
	// A GET on the anonymize endpoint is expected to 405 or 404 — we
	// only care that TCP connect succeeds and we get any HTTP response.
	resp, err := c.Get(url) //nolint:noctx // smoke probe; short per-call timeout is sufficient.
	if err != nil {
		t.Skipf("livewire PII service not reachable at %s: %v", url, err)
	}
	_ = resp.Body.Close()
}

// buildLivewireDispatcher constructs a real Dispatcher pointing at the
// env-configured PII service, with a validated default policy. No Jira
// client — livewire tests do not cover T0 reconstruction because that
// requires credentials.
//
// Why not reuse BuildDispatcher + the default policy directly?
// -----------------------------------------------------------
// BuildDispatcher wires up all five backends by default. That's what
// we want here: the livewire test exercises supportgpt, nurag, glean,
// and the default handler simultaneously, just like production.
func buildLivewireDispatcher(t *testing.T) (*Dispatcher, *contentFilter) {
	t.Helper()

	policy := filterapi.DefaultMCPContentFilterPolicy()
	policy.PII.URL = piiURL(t)
	// DefaultMCPContentFilterPolicy already calls ApplyDefaults; we
	// still call it explicitly here so the URL override above re-seeds
	// dependent defaults. Validate to catch any mis-wiring before we
	// shell out to a GPU service.
	policy.ApplyDefaults()
	require.NoError(t, policy.Validate())

	pii, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 60 * time.Second},
		URL:               policy.PII.URL,
		Timeout:           time.Duration(policy.PII.TimeoutSeconds) * time.Second,
		FailClosed:        false, // livewire is exploratory; don't poison the pipeline
		MaxChars:          policy.PII.MaxCharsPerRequest,
		MaxParallelChunks: policy.PII.MaxParallelChunks,
		Logger:            slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	require.NoError(t, err)

	d := BuildDispatcher(&policy, pii, nil, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	require.NotNil(t, d)

	// contentFilter with dispatcher attached. URL is a dead sentinel
	// that will fail loudly if the dispatcher branch is ever bypassed
	// during a livewire run.
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL: "http://livewire-should-never-hit-http.invalid.",
		Scopes: []filterapi.MCPContentFilterScope{
			filterapi.MCPContentFilterScopeRequest,
			filterapi.MCPContentFilterScopeResponse,
		},
		FailurePolicy:  filterapi.MCPContentFilterFailurePolicyPassThrough,
		ForwardHeaders: []string{"X-Eval-Exclude-Ticket-Id"},
		TimeoutSeconds: 60,
	}, "livewire-route", "livewire-backend")
	require.NoError(t, err)
	cf.WithDispatcher(d)
	return d, cf
}

// --- tests ----------------------------------------------------------

// TestInProcessLivewire_SupportGPTRequestInjection asserts the
// supportgpt Request handler injects the eval ticket into the query
// arguments and routes entirely in-process (no HTTP sidecar contact).
func TestInProcessLivewire_SupportGPTRequestInjection(t *testing.T) {
	_, cf := buildLivewireDispatcher(t)
	hdrs := http.Header{}
	hdrs.Set("X-Eval-Exclude-Ticket-Id", livewireEvalTicket())

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{
			"name":      "search_cases",
			"arguments": map[string]any{"query": "disk corruption"},
		}),
	}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{},
		&http.Client{}, cf,
		"livewire-route", "supportgpt", "search_cases", req, hdrs)
	require.NoError(t, err)
	require.NotSame(t, req, got, "expected in-process redact to rewrite params")
	require.Contains(t, string(got.Params), `"exclude_ticket_ids"`)
	require.Contains(t, string(got.Params), livewireEvalTicket())
}

// TestInProcessLivewire_GleanRequestRewrite confirms the glean handler
// appends the exclude-ticket marker to the query string.
func TestInProcessLivewire_GleanRequestRewrite(t *testing.T) {
	_, cf := buildLivewireDispatcher(t)
	hdrs := http.Header{}
	hdrs.Set("X-Eval-Exclude-Ticket-Id", livewireEvalTicket())

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{
			"name":      "search",
			"arguments": map[string]any{"query": "runbook"},
		}),
	}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{},
		&http.Client{}, cf,
		"livewire-route", "glean", "search", req, hdrs)
	require.NoError(t, err)
	require.Contains(t, string(got.Params), "-ticket:"+livewireEvalTicket())
}

// TestInProcessLivewire_DefaultBackendPIIRedaction verifies that a
// backend in the default PII scan allowlist gets real NER-based
// redaction from the live PII service.
//
// The test is intentionally lenient about the specific tokens: different
// PII service versions emit different placeholders (<PERSON_N>, <PERSON>,
// <EMAIL_N>, <EMAIL>, etc.); we just verify that *something* was redacted.
func TestInProcessLivewire_DefaultBackendPIIRedaction(t *testing.T) {
	requireLivePIIService(t, piiURL(t))
	_, cf := buildLivewireDispatcher(t)

	resp := &jsonrpc.Response{
		ID: makeID(t, float64(1)),
		Result: mustJSON(t, map[string]any{
			"content": []any{map[string]any{
				"type": "text",
				"text": "Contact Jane Doe at jane.doe@example.com re case CX-77",
			}},
		}),
	}
	// "panacea" is in the default PII scan allowlist per the default policy.
	got, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{},
		&http.Client{}, cf,
		"livewire-route", "panacea", "log_summary",
		&jsonrpc.Request{Method: "tools/call"}, resp, http.Header{})
	require.NoError(t, err)
	require.NotSame(t, resp, got, "expected redact from live PII service")

	s := string(got.Result)
	require.True(t,
		strings.Contains(s, "<PERSON") || strings.Contains(s, "<EMAIL"),
		"expected at least one NER placeholder in %q", s,
	)
}

// TestInProcessLivewire_UnknownBackendPassesThrough verifies that a
// backend NOT in the scan allowlist is passed through unchanged —
// matches Python behavior and the HTTP sidecar contract.
func TestInProcessLivewire_UnknownBackendPassesThrough(t *testing.T) {
	_, cf := buildLivewireDispatcher(t)

	req := &jsonrpc.Request{
		ID:     makeID(t, float64(1)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "whatever", "arguments": map[string]any{}}),
	}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{},
		&http.Client{}, cf,
		"livewire-route", "no-such-backend", "whatever", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "unknown backend must pass through unchanged")
}
