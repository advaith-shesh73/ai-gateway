// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Parity tests for the five backend handlers — DefaultHandler,
// SupportGPTHandler, NuRAGHandler, GleanHandler, JiraHandler.
//
// Each test group corresponds one-to-one with a test class in the
// Python reference suite at
// `panacea-agent/services/aigw-content-filter/tests/test_backends/*.py`.
// The assertions are identical in intent so a parity auditor can grep
// for the test name and see the same expectation on both sides.

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// -----------------------------------------------------------------------
// helper: unit tests for the tiny normalizeExcludeList helper, matching
// Python TestNormalizeExcludeList one-for-one.
// -----------------------------------------------------------------------

func TestNormalizeExcludeList(t *testing.T) {
	cases := []struct {
		name string
		in   any
		want []string
	}{
		{"nil", nil, nil},
		{"list", []any{"ENG-1", "ENG-2", ""}, []string{"ENG-1", "ENG-2"}},
		{"list_strips_whitespace", []any{"  ENG-1 ", " ENG-2"}, []string{"ENG-1", "ENG-2"}},
		{"comma_separated_string", "ENG-1,ENG-2, ENG-3 ", []string{"ENG-1", "ENG-2", "ENG-3"}},
		{"single_value_non_string", 42, []string{"42"}},
		{"empty_string", "", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeExcludeList(c.in)
			if !stringSliceEqual(got, c.want) {
				t.Fatalf("normalizeExcludeList(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func stringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// -----------------------------------------------------------------------
// DefaultHandler tests — mirrors tests/test_backends/test_default.py
// -----------------------------------------------------------------------

// requestScopeAlwaysPass asserts the DefaultHandler's request scope is
// unconditionally a pass, regardless of backend name or body shape.
func TestDefaultHandler_Request_AlwaysPass(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewDefaultHandler([]string{"supportgpt"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "any", nil),
		map[string]any{"params": map[string]any{}},
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s (%s)", resp.Action, resp.Reason)
	}
}

func TestDefaultHandler_Response_PassWhenBackendNotInScanSet(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "somethingelse", "", nil),
		makeMCPResponseBody([]string{"John lives in NYC"}),
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Fatalf("expected no PII calls, got %d: %v", len(calls), calls)
	}
}

func TestDefaultHandler_Response_BackendMatchingIsCaseInsensitive(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "SUPPORTGPT", "", nil),
		makeMCPResponseBody([]string{"John lives in NYC"}),
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (%s)", resp.Action, resp.Reason)
	}
}

func TestDefaultHandler_Response_PassWhenNoTextParts(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil)
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{}}},
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
	if calls := fake.Calls(); len(calls) != 0 {
		t.Fatalf("expected no PII calls, got %d", len(calls))
	}
}

func TestDefaultHandler_Response_PassWhenPIIDetectsNothing(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil)
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody([]string{"clean text", "more clean text"}),
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
	if got := len(fake.Calls()); got != 2 {
		t.Fatalf("expected 2 PII calls, got %d", got)
	}
}

func TestDefaultHandler_Response_RedactsEachTextPartIndependently(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{
		"John": "<PERSON>",
		"NYC":  "<LOCATION>",
	})
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody([]string{
			"John lives in NYC",
			"clean",
			"Another John",
		}),
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	texts := backendTextParts(decodeBackendBody(t, resp.Body))
	want := []string{"<PERSON> lives in <LOCATION>", "clean", "Another <PERSON>"}
	if !stringSliceEqual(texts, want) {
		t.Fatalf("texts = %v, want %v", texts, want)
	}
}

func TestDefaultHandler_Response_RejectOnPIIServiceError(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil).WithFailure(errors.New("service down"))
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody([]string{"payload"}),
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionReject {
		t.Fatalf("expected reject, got %s", resp.Action)
	}
	if resp.Code != CodePIIUnavailable {
		t.Fatalf("expected code %d, got %d", CodePIIUnavailable, resp.Code)
	}
}

func TestDefaultHandler_Response_ForwardsPIIContext(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"a": "b"})
	h := NewDefaultHandler([]string{"nurag"})
	obs := newContextRecordingPIIMetrics()
	pii := newPIIClientForBackendWithObserver(t, fake.URL(), obs)
	_ = h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "nurag", "query_knowledge", nil),
		makeMCPResponseBody([]string{"text a"}),
		makeHandlerDeps(pii, nil),
	)
	got := obs.Contexts()
	if len(got) != 1 {
		t.Fatalf("expected 1 PII call, got %d", len(got))
	}
	// Canonical PII context format is scope|route|backend|tool — the
	// tenant-aware form (L06) that isolates cache rows across routes.
	want := BuildPIIContext(ScopeResponse, "test-route", "nurag", "query_knowledge")
	if got[0] != want {
		t.Fatalf("expected context %q, got %q", want, got[0])
	}
}

func TestDefaultHandler_Response_SkipsNonTextContentParts(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result": map[string]any{
			"content": []any{
				map[string]any{"type": "text", "text": "John is here"},
				map[string]any{"type": "image", "data": "base64blob"},
				map[string]any{"type": "text", "text": "John again"},
			},
		},
	}
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	newBody := decodeBackendBody(t, resp.Body)
	content := newBody["result"].(map[string]any)["content"].([]any)
	if c0, _ := content[0].(map[string]any); c0["text"] != "<PERSON> is here" {
		t.Fatalf("part 0 = %v", c0)
	}
	if c1, _ := content[1].(map[string]any); c1["type"] != "image" {
		t.Fatalf("image part mutated: %v", c1)
	}
	if c2, _ := content[2].(map[string]any); c2["text"] != "<PERSON> again" {
		t.Fatalf("part 2 = %v", c2)
	}
}

// Parallel-fanout properties matching
// TestDefaultHandlerParallelFanout in the Python suite.

func TestDefaultHandler_Response_PeakConcurrencyRespectsBound(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	const maxParallel = 3
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"pii": "<PII>"}).
		WithDelay(20 * time.Millisecond)
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())

	deps := makeHandlerDeps(pii, nil)
	deps.Policy.PII.MaxParallelParts = maxParallel

	texts := make([]string, 12)
	for i := range texts {
		texts[i] = "pii-" + intToStr(i)
	}
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody(texts),
		deps,
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	if got := fake.PeakConcurrency(); got > maxParallel {
		t.Fatalf("peak %d exceeded bound %d", got, maxParallel)
	}
	if got := fake.PeakConcurrency(); got < 2 {
		t.Fatalf("no parallelism observed; peak=%d (handler running serial)", got)
	}
	if got := len(fake.Calls()); got != 12 {
		t.Fatalf("expected 12 calls, got %d", got)
	}
}

func TestDefaultHandler_Response_SerialWhenBoundIsOne(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"x": "<X>"}).
		WithDelay(5 * time.Millisecond)
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())

	deps := makeHandlerDeps(pii, nil)
	deps.Policy.PII.MaxParallelParts = 1

	texts := []string{"x-0", "x-1", "x-2", "x-3", "x-4"}
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody(texts),
		deps,
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	if got := fake.PeakConcurrency(); got != 1 {
		t.Fatalf("peak concurrency = %d, want 1", got)
	}
}

func TestDefaultHandler_Response_SparseReplacementsOnlyRewriteChangedParts(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"SECRET": "<REDACTED>"})
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody([]string{
			"clean one",
			"clean two",
			"SECRET here",
			"clean four",
			"clean five",
		}),
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	texts := backendTextParts(decodeBackendBody(t, resp.Body))
	want := []string{
		"clean one",
		"clean two",
		"<REDACTED> here",
		"clean four",
		"clean five",
	}
	if !stringSliceEqual(texts, want) {
		t.Fatalf("texts = %v, want %v", texts, want)
	}
}

func TestDefaultHandler_Response_SinglePartFailureAbortsWholeResponse(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"clean": "<C>"}).
		WithDelay(5 * time.Millisecond).
		WithFailOnText("boom")
	h := NewDefaultHandler([]string{"supportgpt"})
	pii := newPIIClientForBackend(t, fake.URL())

	deps := makeHandlerDeps(pii, nil)
	deps.Policy.PII.MaxParallelParts = 4

	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		makeMCPResponseBody([]string{"clean a", "clean b", "boom here", "clean c", "clean d"}),
		deps,
	)
	if resp.Action != ActionReject {
		t.Fatalf("expected reject on one-bad-part, got %s", resp.Action)
	}
	if resp.Code != CodePIIUnavailable {
		t.Fatalf("expected code %d, got %d", CodePIIUnavailable, resp.Code)
	}
}

func TestDefaultHandler_Response_AllPartsGetSameContext(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"z": "<Z>"})
	h := NewDefaultHandler([]string{"supportgpt"})
	obs := newContextRecordingPIIMetrics()
	pii := newPIIClientForBackendWithObserver(t, fake.URL(), obs)
	texts := make([]string, 8)
	for i := range texts {
		texts[i] = "z" + intToStr(i)
	}
	_ = h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "search_cases", nil),
		makeMCPResponseBody(texts),
		makeHandlerDeps(pii, nil),
	)
	contexts := obs.Contexts()
	if len(contexts) != 8 {
		t.Fatalf("expected 8 PII calls, got %d", len(contexts))
	}
	seen := map[string]struct{}{}
	for _, c := range contexts {
		seen[c] = struct{}{}
	}
	want := BuildPIIContext(ScopeResponse, "test-route", "supportgpt", "search_cases")
	if _, ok := seen[want]; !ok || len(seen) != 1 {
		t.Fatalf("expected exactly one context %q, got %v", want, seen)
	}
	if got := len(fake.Calls()); got != 8 {
		t.Fatalf("expected 8 wire calls, got %d", got)
	}
}

// -----------------------------------------------------------------------
// SupportGPTHandler tests — mirrors tests/test_backends/test_supportgpt.py
// -----------------------------------------------------------------------

func TestSupportGPT_Request_EvalInactive_Passes(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	body := makeMCPRequestBody("search_cases", map[string]any{"q": "x"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "search_cases", nil),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
	if !strings.Contains(resp.Reason, "eval mode inactive") {
		t.Fatalf("reason = %q, want 'eval mode inactive'", resp.Reason)
	}
}

func TestSupportGPT_Request_UnknownTool_Passes(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	body := makeMCPRequestBody("some_weird_tool", map[string]any{"q": "x"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "some_weird_tool",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestSupportGPT_Request_AllSearchToolsGetExclusionInjected(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	for tool := range supportGPTExcludeSearchTools {
		t.Run(tool, func(t *testing.T) {
			body := makeMCPRequestBody(tool, map[string]any{"q": "error"})
			resp := h.HandleRequest(
				ctx,
				makeBackendRequest(ScopeRequest, "supportgpt", tool,
					map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
				body,
				makeHandlerDeps(nil, nil),
			)
			if resp.Action != ActionRedact {
				t.Fatalf("expected redact, got %s", resp.Action)
			}
			newBody := decodeBackendBody(t, resp.Body)
			args := newBody["params"].(map[string]any)["arguments"].(map[string]any)
			excl, _ := args["exclude_ticket_ids"].([]any)
			if len(excl) != 1 || excl[0] != "ENG-1" {
				t.Fatalf("exclude_ticket_ids = %v", excl)
			}
		})
	}
}

func TestSupportGPT_Request_MergesWithExistingList(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	body := makeMCPRequestBody("search_cases", map[string]any{
		"q":                  "x",
		"exclude_ticket_ids": []any{"ENG-2", "ENG-3"},
	})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "search_cases",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	excl, _ := args["exclude_ticket_ids"].([]any)
	want := []any{"ENG-2", "ENG-3", "ENG-1"}
	if !anySliceEqual(excl, want) {
		t.Fatalf("exclude_ticket_ids = %v, want %v", excl, want)
	}
}

func TestSupportGPT_Request_MergesWithCommaString(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	body := makeMCPRequestBody("search_cases", map[string]any{
		"q":                  "x",
		"exclude_ticket_ids": "ENG-2, ENG-3",
	})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "search_cases",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	excl, _ := args["exclude_ticket_ids"].([]any)
	want := []any{"ENG-2", "ENG-3", "ENG-1"}
	if !anySliceEqual(excl, want) {
		t.Fatalf("exclude_ticket_ids = %v, want %v", excl, want)
	}
}

func TestSupportGPT_Request_IdempotentWhenAlreadyExcluded(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	body := makeMCPRequestBody("search_cases", map[string]any{
		"q":                  "x",
		"exclude_ticket_ids": []any{"ENG-1"},
	})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "search_cases",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass (idempotent), got %s", resp.Action)
	}
}

func TestSupportGPT_Request_RespectsCustomEvalHeaderName(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	body := makeMCPRequestBody("search_cases", nil)
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "supportgpt", "search_cases",
			map[string]string{"x-custom-eval": "ENG-1"}),
		body,
		makeHandlerDepsWithEvalHeader(nil, nil, "x-custom-eval", false),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	excl, _ := args["exclude_ticket_ids"].([]any)
	if len(excl) != 1 || excl[0] != "ENG-1" {
		t.Fatalf("exclude = %v", excl)
	}
}

// ── response-scope tests ────────────────────────────────────────────

func TestSupportGPT_Response_NoTextPartsPass(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewSupportGPTHandler()
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{"content": []any{}}},
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestSupportGPT_Response_SubstringScrubsEvalTicket(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil)
	h := NewSupportGPTHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{
		"similar to ENG-1 with root cause",
		"unrelated text",
	})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	texts := backendTextParts(decodeBackendBody(t, resp.Body))
	if !strings.Contains(texts[0], REDACTEvalTicketTag) {
		t.Fatalf("part 0 missing redact tag: %q", texts[0])
	}
	if strings.Contains(texts[0], "ENG-1") {
		t.Fatalf("part 0 still contains ENG-1: %q", texts[0])
	}
	if texts[1] != "unrelated text" {
		t.Fatalf("part 1 = %q", texts[1])
	}
}

func TestSupportGPT_Response_PIIScanOnTopOfSubstringScrub(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewSupportGPTHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"ENG-1 case for John"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if !strings.Contains(text, REDACTEvalTicketTag) {
		t.Fatalf("text missing redact tag: %q", text)
	}
	if !strings.Contains(text, "<PERSON>") {
		t.Fatalf("text missing <PERSON>: %q", text)
	}
	if strings.Contains(text, "ENG-1") || strings.Contains(text, "John") {
		t.Fatalf("text still leaks: %q", text)
	}

	// The PII server must have seen text with ticket already scrubbed.
	for _, call := range fake.Calls() {
		if strings.Contains(call.Text, "ENG-1") {
			t.Fatalf("PII server saw raw ticket: %q", call.Text)
		}
	}
}

func TestSupportGPT_Response_NoEvalTicketStillRunsPIIScan(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewSupportGPTHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"Call John"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if text != "Call <PERSON>" {
		t.Fatalf("text = %q", text)
	}
}

func TestSupportGPT_Response_PassWhenNoRedactionsNeeded(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil)
	h := NewSupportGPTHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"all clean", "more clean"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-99"}),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestSupportGPT_Response_RejectWhenPIIServiceUnavailable(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil).WithFailure(errors.New("down"))
	h := NewSupportGPTHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"payload"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionReject || resp.Code != CodePIIUnavailable {
		t.Fatalf("expected reject code=%d, got %s / %d", CodePIIUnavailable, resp.Action, resp.Code)
	}
}

func TestSupportGPT_Response_MultipleOccurrencesAllReplaced(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil)
	h := NewSupportGPTHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"ENG-1 is like ENG-1 and ENG-1"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "supportgpt", "",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if strings.Count(text, REDACTEvalTicketTag) != 3 {
		t.Fatalf("expected 3 tags, got %d in %q", strings.Count(text, REDACTEvalTicketTag), text)
	}
	if strings.Contains(text, "ENG-1") {
		t.Fatalf("text still leaks: %q", text)
	}
}

// -----------------------------------------------------------------------
// NuRAGHandler tests — mirrors tests/test_backends/test_nurag.py
// -----------------------------------------------------------------------

func TestNuRAG_Request_EvalInactivePasses(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewNuRAGHandler()
	body := makeMCPRequestBody("query_knowledge", map[string]any{"query": "foo"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "nurag", "query_knowledge", nil),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestNuRAG_Request_NonTicketKeyEvalTicketPasses(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewNuRAGHandler()
	body := makeMCPRequestBody("query_knowledge", map[string]any{"query": "foo"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "nurag", "query_knowledge",
			map[string]string{"x-eval-exclude-ticket-id": "not-a-ticket"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestNuRAG_Request_UnknownTool_Passes(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewNuRAGHandler()
	body := makeMCPRequestBody("random_tool", map[string]any{"query": "foo"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "nurag", "random_tool",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestNuRAG_Request_InjectsExcludeSources(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewNuRAGHandler()
	body := makeMCPRequestBody("query_knowledge", map[string]any{"query": "foo"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "nurag", "query_knowledge",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (%s)", resp.Action, resp.Reason)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	excl, _ := args["exclude_sources"].([]any)
	if len(excl) != 1 || excl[0] != "ENG-1" {
		t.Fatalf("exclude_sources = %v", excl)
	}
}

func TestNuRAG_Request_MergesWithExistingExcludeSources(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewNuRAGHandler()
	body := makeMCPRequestBody("query_knowledge", map[string]any{
		"query":           "foo",
		"exclude_sources": []any{"OTHER-1"},
	})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "nurag", "query_knowledge",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	excl, _ := args["exclude_sources"].([]any)
	want := []any{"OTHER-1", "ENG-1"}
	if !anySliceEqual(excl, want) {
		t.Fatalf("exclude_sources = %v, want %v", excl, want)
	}
}

func TestNuRAG_Request_IdempotentWhenAlreadyExcluded(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewNuRAGHandler()
	body := makeMCPRequestBody("query_knowledge", map[string]any{
		"query":           "foo",
		"exclude_sources": []any{"ENG-1"},
	})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "nurag", "query_knowledge",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass (idempotent), got %s", resp.Action)
	}
}

func TestNuRAG_Response_RunsPIIScan(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"Jane": "<PERSON>"})
	h := NewNuRAGHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"Meet Jane"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "nurag", "query_knowledge", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if text != "Meet <PERSON>" {
		t.Fatalf("text = %q", text)
	}
}

// -----------------------------------------------------------------------
// GleanHandler tests — mirrors tests/test_backends/test_glean.py
// -----------------------------------------------------------------------

func TestGlean_Request_EvalInactivePasses(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewGleanHandler()
	body := makeMCPRequestBody("search", map[string]any{"query": "hello"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "glean", "search", nil),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestGlean_Request_UnknownTool_Passes(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewGleanHandler()
	body := makeMCPRequestBody("unknown_tool", map[string]any{"query": "hello"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "glean", "unknown_tool",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestGlean_Request_AppendsTicketExclusionToQuery(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewGleanHandler()
	body := makeMCPRequestBody("search", map[string]any{"query": "how to deploy"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "glean", "search",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	q, _ := args["query"].(string)
	if q != "how to deploy -ticket:ENG-1" {
		t.Fatalf("query = %q", q)
	}
}

func TestGlean_Request_UsesQKeyIfQueryAbsent(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewGleanHandler()
	body := makeMCPRequestBody("search", map[string]any{"q": "how to deploy"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "glean", "search",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	q, _ := args["q"].(string)
	if q != "how to deploy -ticket:ENG-1" {
		t.Fatalf("q = %q", q)
	}
}

func TestGlean_Request_IdempotentWhenExclusionAlreadyPresent(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewGleanHandler()
	body := makeMCPRequestBody("search", map[string]any{"query": "foo -ticket:ENG-1 bar"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "glean", "search",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass (idempotent), got %s", resp.Action)
	}
}

func TestGlean_Response_RunsPIIScan(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewGleanHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"John is here"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "glean", "search", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if text != "<PERSON> is here" {
		t.Fatalf("text = %q", text)
	}
}

// -----------------------------------------------------------------------
// JiraHandler tests — mirrors tests/test_backends/test_jira.py
// -----------------------------------------------------------------------

// ── helper-function tests ──────────────────────────────────────────

func TestTicketKeyFromArgs(t *testing.T) {
	aliases := []string{
		"issueIdOrKey", "issueKey", "issue_id_or_key", "issue_key", "key", "id",
	}
	for _, key := range aliases {
		t.Run(key, func(t *testing.T) {
			got := ticketKeyFromArgs(map[string]any{key: "ENG-1"})
			if got != "ENG-1" {
				t.Fatalf("ticketKeyFromArgs(%q) = %q", key, got)
			}
		})
	}
	t.Run("prefers_first_alias", func(t *testing.T) {
		got := ticketKeyFromArgs(map[string]any{
			"issueIdOrKey": "PRIMARY-1", "key": "SECONDARY-1",
		})
		if got != "PRIMARY-1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("strips_whitespace", func(t *testing.T) {
		got := ticketKeyFromArgs(map[string]any{"issueIdOrKey": "  ENG-1  "})
		if got != "ENG-1" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("returns_empty_when_no_alias_found", func(t *testing.T) {
		got := ticketKeyFromArgs(map[string]any{})
		if got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("ignores_non_string_values", func(t *testing.T) {
		got := ticketKeyFromArgs(map[string]any{"issueIdOrKey": 123})
		if got != "" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestJqlFromArgs(t *testing.T) {
	t.Run("prefers_jql", func(t *testing.T) {
		key, val := jqlFromArgs(map[string]any{"jql": "project = ENG"})
		if key != "jql" || val != "project = ENG" {
			t.Fatalf("got %q/%q", key, val)
		}
	})
	t.Run("falls_back_to_query", func(t *testing.T) {
		key, val := jqlFromArgs(map[string]any{"query": "project = ENG"})
		if key != "query" || val != "project = ENG" {
			t.Fatalf("got %q/%q", key, val)
		}
	})
	t.Run("prefers_jql_when_both_present", func(t *testing.T) {
		key, val := jqlFromArgs(map[string]any{"jql": "A", "query": "B"})
		if key != "jql" || val != "A" {
			t.Fatalf("got %q/%q", key, val)
		}
	})
	t.Run("defaults_to_empty_jql", func(t *testing.T) {
		key, val := jqlFromArgs(map[string]any{})
		if key != "jql" || val != "" {
			t.Fatalf("got %q/%q", key, val)
		}
	})
}

func TestGuessTicketKeyFromResult(t *testing.T) {
	t.Run("finds_json_key_in_text_part", func(t *testing.T) {
		body := makeMCPResponseBody([]string{`{"key":"ENG-42","other":1}`})
		got := guessTicketKeyFromResult(body)
		if got != "ENG-42" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("skips_non_json_text", func(t *testing.T) {
		body := makeMCPResponseBody([]string{"not json", `{"key":"ENG-42"}`})
		got := guessTicketKeyFromResult(body)
		if got != "ENG-42" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("returns_empty_when_no_match", func(t *testing.T) {
		body := makeMCPResponseBody([]string{"not json at all"})
		got := guessTicketKeyFromResult(body)
		if got != "" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("returns_empty_when_key_is_not_ticket_key", func(t *testing.T) {
		body := makeMCPResponseBody([]string{`{"key":"short"}`})
		got := guessTicketKeyFromResult(body)
		if got != "" {
			t.Fatalf("got %q", got)
		}
	})
}

// ── request-scope handler tests ─────────────────────────────────────

func TestJira_Request_EvalInactive_Passes(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewJiraHandler()
	body := makeMCPRequestBody("searchJiraIssuesUsingJql", map[string]any{"jql": "x"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "jira", "searchJiraIssuesUsingJql", nil),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestJira_Request_GetIssueRequestScopeIsNoop(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewJiraHandler()
	body := makeMCPRequestBody("getJiraIssue", map[string]any{"issueIdOrKey": "ENG-1"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "jira", "getJiraIssue",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass, got %s", resp.Action)
	}
}

func TestJira_Request_JQLRewrittenInAllSearchTools(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewJiraHandler()
	for tool := range jiraSearchJQLTools {
		t.Run(tool, func(t *testing.T) {
			body := makeMCPRequestBody(tool, map[string]any{"jql": "project = ENG"})
			resp := h.HandleRequest(
				ctx,
				makeBackendRequest(ScopeRequest, "jira", tool,
					map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
				body,
				makeHandlerDeps(nil, nil),
			)
			if resp.Action != ActionRedact {
				t.Fatalf("expected redact, got %s", resp.Action)
			}
			args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
			jql, _ := args["jql"].(string)
			if jql != `(project = ENG) AND key != "ENG-1"` {
				t.Fatalf("jql = %q", jql)
			}
		})
	}
}

func TestJira_Request_JQLRewriteUsesQueryWhenJQLMissing(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewJiraHandler()
	body := makeMCPRequestBody("searchJiraIssuesUsingJql",
		map[string]any{"query": "project = ENG"})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "jira", "searchJiraIssuesUsingJql",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	args := decodeBackendBody(t, resp.Body)["params"].(map[string]any)["arguments"].(map[string]any)
	q, _ := args["query"].(string)
	if q != `(project = ENG) AND key != "ENG-1"` {
		t.Fatalf("query = %q", q)
	}
}

func TestJira_Request_JQLRewriteIdempotent(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	h := NewJiraHandler()
	body := makeMCPRequestBody("searchJiraIssuesUsingJql",
		map[string]any{"jql": `(project = ENG) AND key != "ENG-1"`})
	resp := h.HandleRequest(
		ctx,
		makeBackendRequest(ScopeRequest, "jira", "searchJiraIssuesUsingJql",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(nil, nil),
	)
	if resp.Action != ActionPass {
		t.Fatalf("expected pass (idempotent), got %s", resp.Action)
	}
}

// ── response-scope: PII-only path ───────────────────────────────────

func TestJira_Response_UnrelatedToolRunsPIIScan(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewJiraHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"see John"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "jira", "other_tool", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if text != "see <PERSON>" {
		t.Fatalf("text = %q", text)
	}
}

func TestJira_Response_PIIRejectOnFailure(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, nil).WithFailure(errors.New("down"))
	h := NewJiraHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"payload"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "jira", "other_tool", nil),
		body,
		makeHandlerDeps(pii, nil),
	)
	if resp.Action != ActionReject || resp.Code != CodePIIUnavailable {
		t.Fatalf("expected reject code=%d, got %s/%d", CodePIIUnavailable, resp.Action, resp.Code)
	}
}

func TestJira_Response_NoJiraClientConfiguredFallsBackToPII(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	h := NewJiraHandler()
	pii := newPIIClientForBackend(t, fake.URL())
	body := makeMCPResponseBody([]string{"see John"})
	resp := h.HandleResponse(
		ctx,
		makeBackendRequest(ScopeResponse, "jira", "getJiraIssue",
			map[string]string{"x-eval-exclude-ticket-id": "ENG-1"}),
		body,
		makeHandlerDeps(pii, nil), // deps.Jira == nil on purpose
	)
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if text != "see <PERSON>" {
		t.Fatalf("text = %q", text)
	}
}

// ── response-scope: T0 reconstruction ───────────────────────────────

func newT0Issue() map[string]any {
	return map[string]any{
		"id":   "10001",
		"key":  "ENG-1",
		"self": "https://jira/rest/api/3/issue/10001",
		"fields": map[string]any{
			"summary":     "Original summary",
			"description": "Original desc",
			"status":      map[string]any{"name": "In Progress"},
		},
		"changelog": map[string]any{
			"histories": []any{
				map[string]any{
					"created": "2025-02-01T00:00:00Z",
					"items": []any{
						map[string]any{
							"field":      "summary",
							"fromString": "T0 summary",
							"toString":   "Original summary",
						},
					},
				},
			},
		},
	}
}

func TestJira_Response_GetIssueReturnsT0(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	for tool := range jiraGetIssueTools {
		t.Run(tool, func(t *testing.T) {
			srv := newJiraTestBackendServer(t, "ENG-1", newT0Issue())
			jira := newJiraClientForBackend(t, srv.URL)
			h := NewJiraHandler()

			original := makeMCPResponseBody([]string{
				`{"key":"ENG-1","fields":{"summary":"post-creation"}}`,
			})
			req := makeBackendRequest(ScopeResponse, "jira", tool,
				map[string]string{
					"x-eval-exclude-ticket-id":   "ENG-1",
					"x-aigwcf-request-arguments": makeArgumentsHeader(t, tool, map[string]any{"issueIdOrKey": "ENG-1"}),
				})
			resp := h.HandleResponse(ctx, req, original, makeHandlerDeps(nil, jira))
			if resp.Action != ActionRedact {
				t.Fatalf("expected redact, got %s (%s)", resp.Action, resp.Reason)
			}
			text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
			var reconstructed map[string]any
			if err := json.Unmarshal([]byte(text), &reconstructed); err != nil {
				t.Fatalf("decode reconstructed: %v", err)
			}
			if reconstructed["key"] != "ENG-1" {
				t.Fatalf("key = %v", reconstructed["key"])
			}
			if reconstructed["t0_reconstructed"] != true {
				t.Fatalf("t0_reconstructed = %v", reconstructed["t0_reconstructed"])
			}
			fields, _ := reconstructed["fields"].(map[string]any)
			if fields["summary"] != "T0 summary" {
				t.Fatalf("fields.summary = %v", fields["summary"])
			}
			if _, ok := fields["status"]; ok {
				t.Fatalf("fields.status should be dropped, got %v", fields["status"])
			}
		})
	}
}

func TestJira_Response_RejectOnJiraError(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	failingSrv := startAlwaysFailServer(t)
	jira := newJiraClientForBackend(t, failingSrv.URL())
	h := NewJiraHandler()

	body := makeMCPResponseBody([]string{"old"})
	req := makeBackendRequest(ScopeResponse, "jira", "getJiraIssue",
		map[string]string{
			"x-eval-exclude-ticket-id":   "ENG-1",
			"x-aigwcf-request-arguments": makeArgumentsHeader(t, "getJiraIssue", map[string]any{"issueIdOrKey": "ENG-1"}),
		})
	resp := h.HandleResponse(ctx, req, body, makeHandlerDeps(nil, jira))
	if resp.Action != ActionReject {
		t.Fatalf("expected reject, got %s", resp.Action)
	}
	if resp.Code != CodeJiraUnavailable {
		t.Fatalf("expected code %d, got %d", CodeJiraUnavailable, resp.Code)
	}
}

func TestJira_Response_DifferentTicketThanEvalIDUsesPIIPath(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	srv := newJiraTestBackendServer(t, "ENG-1", newT0Issue())
	jira := newJiraClientForBackend(t, srv.URL)
	fake := newReplaceMapPIIFakeServer(t, map[string]string{"John": "<PERSON>"})
	pii := newPIIClientForBackend(t, fake.URL())
	h := NewJiraHandler()

	body := makeMCPResponseBody([]string{"Call John"})
	req := makeBackendRequest(ScopeResponse, "jira", "getJiraIssue",
		map[string]string{
			"x-eval-exclude-ticket-id":   "ENG-1",
			"x-aigwcf-request-arguments": makeArgumentsHeader(t, "getJiraIssue", map[string]any{"issueIdOrKey": "OTHER-1"}),
		})
	resp := h.HandleResponse(ctx, req, body, makeHandlerDeps(pii, jira))
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s", resp.Action)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if text != "Call <PERSON>" {
		t.Fatalf("text = %q", text)
	}
}

func TestJira_Response_FallbackToResponseGuessWhenRequestArgsMissing(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()
	srv := newJiraTestBackendServer(t, "ENG-1", newT0Issue())
	jira := newJiraClientForBackend(t, srv.URL)
	h := NewJiraHandler()

	original := makeMCPResponseBody([]string{
		`{"key":"ENG-1","fields":{}}`,
	})
	req := makeBackendRequest(ScopeResponse, "jira", "getJiraIssue",
		map[string]string{"x-eval-exclude-ticket-id": "ENG-1"})
	resp := h.HandleResponse(ctx, req, original, makeHandlerDeps(nil, jira))
	if resp.Action != ActionRedact {
		t.Fatalf("expected redact, got %s (%s)", resp.Action, resp.Reason)
	}
	text := backendTextParts(decodeBackendBody(t, resp.Body))[0]
	if !strings.Contains(text, `"t0_reconstructed":true`) && !strings.Contains(text, `"t0_reconstructed": true`) {
		t.Fatalf("missing t0_reconstructed in %q", text)
	}
}

// -----------------------------------------------------------------------
// Multi-valued eval header / strict-mode invariants
// -----------------------------------------------------------------------

func TestBackend_StrictMultiValuedEvalHeaderRejects(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	// Hand-build HeaderView with two non-empty values for the eval
	// header; NewHeaderView will mark it multi-valued.
	raw := map[string][]string{
		"x-eval-exclude-ticket-id": {"ENG-1", "ENG-2"},
	}
	req := &FilterRequest{
		Route:     "test",
		Backend:   "supportgpt",
		Scope:     ScopeRequest,
		MCPMethod: "tools/call",
		Tool:      "search_cases",
		Headers:   NewHeaderView(raw),
	}
	body := makeMCPRequestBody("search_cases", nil)
	h := NewSupportGPTHandler()
	deps := makeHandlerDepsWithEvalHeader(nil, nil, "x-eval-exclude-ticket-id", true)
	resp := h.HandleRequest(ctx, req, body, deps)
	if resp.Action != ActionReject {
		t.Fatalf("expected reject, got %s", resp.Action)
	}
	if resp.Code != CodeInvalidRequest {
		t.Fatalf("expected code %d, got %d", CodeInvalidRequest, resp.Code)
	}
}

// -----------------------------------------------------------------------
// Cross-handler integration: running all five against a single PII fake
// should not leak across (different piiContext keys)
// -----------------------------------------------------------------------

func TestAllHandlers_DistinctPIIContexts(t *testing.T) {
	ctx, cancel := ctxTODO()
	defer cancel()

	fake := newReplaceMapPIIFakeServer(t, map[string]string{"PII": "<PII>"})
	obs := newContextRecordingPIIMetrics()
	pii := newPIIClientForBackendWithObserver(t, fake.URL(), obs)
	deps := makeHandlerDeps(pii, nil)

	handlers := []Handler{
		NewDefaultHandler([]string{"supportgpt", "nurag", "glean", "jira"}),
		NewSupportGPTHandler(),
		NewNuRAGHandler(),
		NewGleanHandler(),
		NewJiraHandler(),
	}
	backends := []string{"supportgpt", "supportgpt", "nurag", "glean", "jira"}
	tools := []string{"tool-X", "search_cases", "query_knowledge", "search", "other_tool"}

	for i, h := range handlers {
		body := makeMCPResponseBody([]string{"Has PII: X"})
		req := makeBackendRequest(ScopeResponse, backends[i], tools[i], nil)
		_ = h.HandleResponse(ctx, req, body, deps)
	}

	contexts := map[string]int{}
	for _, c := range obs.Contexts() {
		contexts[c]++
	}
	if len(contexts) < 4 {
		t.Fatalf("expected at least 4 distinct pii contexts, got %v", contexts)
	}
}

// -----------------------------------------------------------------------
// Tiny utility helpers used by the tests above
// -----------------------------------------------------------------------

func intToStr(i int) string {
	// Avoid pulling in strconv at the top of a test file; the tests
	// only need a base-10 conversion for small positive ints.
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var digits [20]byte
	n := 0
	for i > 0 {
		digits[n] = byte('0' + i%10)
		i /= 10
		n++
	}
	if neg {
		digits[n] = '-'
		n++
	}
	// Reverse.
	out := make([]byte, n)
	for j := 0; j < n; j++ {
		out[j] = digits[n-1-j]
	}
	return string(out)
}

func anySliceEqual(a, b []any) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// prevent unused-import lint if helper set changes.
var (
	_ = atomic.AddInt64
	_ = context.Background
)
