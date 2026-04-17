// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter/wire"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// testConfig returns a Config suitable for policy tests: minimum
// set of validated fields, with one tool in the allowlist and a
// deterministic ticket id.
func testConfig(tools ...string) Config {
	return Config{
		Endpoint:      "http://llm.invalid/chat/completions",
		Model:         "test-model",
		APIKeyEnv:     "CF_TEST_KEY",
		FilteredTools: tools,
		EvalTicketID:  "ENG-TEST-1",
	}
}

// newFilterRequestBody builds a FilterRequest with the given
// JSON-RPC response body under Scope=Response. Kept as a helper so
// each test reads cleanly at the call site.
func newFilterRequestBody(t *testing.T, tool string, result any) *wire.FilterRequest {
	t.Helper()
	resultRaw, err := json.Marshal(result)
	require.NoError(t, err)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, string(resultRaw))
	return &wire.FilterRequest{
		Route:       "r",
		Backend:     "b",
		Scope:       string(wire.ScopeResponse),
		MCPMethod:   "tools/call",
		Tool:        tool,
		Headers:     map[string][]string{},
		BodyBase64:  base64.StdEncoding.EncodeToString([]byte(body)),
		ContentType: "application/json",
	}
}

// TestEvalPolicy_Filter_RequestScopeAlwaysPasses ensures we never
// LLM-call request bodies. PR 95 only ran on postToolUse; we
// preserve that asymmetry.
func TestEvalPolicy_Filter_RequestScopeAlwaysPasses(t *testing.T) {
	stub := &stubLLMClient{}
	p := newWithClient(testConfig("jira_get_issue"), stub)

	req := newFilterRequestBody(t, "jira_get_issue", map[string]any{"content": []any{map[string]any{"type": "text", "text": "x"}}})
	req.Scope = string(wire.ScopeRequest)

	resp, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, string(wire.ActionPass), resp.Action)
	require.Equal(t, 0, stub.calls, "Request-scope must never invoke the LLM")
}

// TestEvalPolicy_Filter_ToolOutsideAllowlistPasses mirrors PR 95's
// test_pass_through_for_unconfigured_tool.
func TestEvalPolicy_Filter_ToolOutsideAllowlistPasses(t *testing.T) {
	stub := &stubLLMClient{}
	p := newWithClient(testConfig("jira_get_issue"), stub)

	req := newFilterRequestBody(t, "some_other_tool",
		map[string]any{"content": []any{map[string]any{"type": "text", "text": "x"}}})

	resp, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, string(wire.ActionPass), resp.Action)
	require.Equal(t, 0, stub.calls)
}

// TestEvalPolicy_Filter_HappyPathRedacts ports PR 95's
// test_filters_configured_tool into the gateway envelope.
func TestEvalPolicy_Filter_HappyPathRedacts(t *testing.T) {
	inner := `{"summary":"dirty","root_cause":"leak"}`
	llmResp := fmt.Sprintf(`{"summary":"dirty","root_cause":"%s"}`, redactedMarker)
	stub := &stubLLMClient{response: llmResp}

	p := newWithClient(testConfig("jira_get_issue"), stub)

	wrapper := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": inner}},
		"isError": false,
	}
	req := newFilterRequestBody(t, "jira_get_issue", wrapper)

	resp, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, string(wire.ActionRedact), resp.Action)
	require.NotEmpty(t, resp.BodyBase64)
	require.Equal(t, 1, stub.calls)

	// Decode the redacted body and verify the inner text has been
	// replaced.
	raw, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
	require.NoError(t, err)

	var decoded struct {
		Jsonrpc string          `json:"jsonrpc"`
		ID      any             `json:"id"`
		Result  json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Equal(t, "2.0", decoded.Jsonrpc)
	require.NotNil(t, decoded.ID)

	_, w := parseMCPOutput(string(decoded.Result))
	require.NotNil(t, w)
	require.Equal(t, llmResp, w.Content[0].Text)
}

// TestEvalPolicy_Filter_LLMFailureFallsBackToSafeRedaction mirrors
// PR 95's test_llm_failure_returns_safe_redaction (and _timeout_error
// and _value_error, which reduce to the same case).
func TestEvalPolicy_Filter_LLMFailureFallsBackToSafeRedaction(t *testing.T) {
	stub := &stubLLMClient{err: errors.New("LLM down")}
	p := newWithClient(testConfig("jira_get_issue"), stub)

	wrapper := map[string]any{
		"content": []any{map[string]any{"type": "text", "text": `{"root_cause":"leak"}`}},
	}
	req := newFilterRequestBody(t, "jira_get_issue", wrapper)

	resp, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, string(wire.ActionRedact), resp.Action)
	require.Contains(t, resp.Reason, "safe redaction")

	raw, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
	require.NoError(t, err)

	var decoded struct {
		Result json.RawMessage `json:"result"`
	}
	require.NoError(t, json.Unmarshal(raw, &decoded))
	_, w := parseMCPOutput(string(decoded.Result))
	require.NotNil(t, w)
	require.Equal(t, filterUnavailableText, w.Content[0].Text,
		"safe redaction must replace the tool output with the unavailable sentinel")
}

// TestEvalPolicy_Filter_NonMCPResultEntersSafeRedaction covers the
// defensive path: if the LLM returns non-JSON for a non-wrapped
// result, we must not leak the original and must still produce a
// valid JSON envelope.
func TestEvalPolicy_Filter_NonMCPResultEntersSafeRedaction(t *testing.T) {
	stub := &stubLLMClient{response: "completely invalid json no braces"}
	p := newWithClient(testConfig("query_knowledge"), stub)

	// Simple non-MCP result.
	req := newFilterRequestBody(t, "query_knowledge", map[string]any{"plain": "string"})

	resp, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, string(wire.ActionRedact), resp.Action)

	// Body must be valid JSON.
	raw, err := base64.StdEncoding.DecodeString(resp.BodyBase64)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &decoded),
		"redacted body must always be valid JSON; got %q", string(raw))

	// Result must carry the sentinel.
	resultJSON, err := json.Marshal(decoded["result"])
	require.NoError(t, err)
	require.Contains(t, string(resultJSON), filterUnavailableText)
}

// TestEvalPolicy_Filter_HeaderTicketOverridesConfig proves the
// forwarded-header precedence: a request carrying
// X-Eval-Ticket-Id=ENG-999 should cause the prompt to stamp ENG-999
// rather than the Config.EvalTicketID.
func TestEvalPolicy_Filter_HeaderTicketOverridesConfig(t *testing.T) {
	stub := &stubLLMClient{response: `{"k":1}`}
	p := newWithClient(testConfig("jira_get_issue"), stub)

	req := newFilterRequestBody(t, "jira_get_issue",
		map[string]any{"content": []any{map[string]any{"type": "text", "text": `{"k":1}`}}})
	req.Headers = map[string][]string{
		"X-Eval-Ticket-Id": {"ENG-999"},
	}

	_, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Contains(t, stub.capturedUser, "ENG-999")
	require.NotContains(t, stub.capturedUser, "ENG-TEST-1")
}

// TestEvalPolicy_Filter_BadBase64ReturnsError checks the defensive
// envelope: malformed base64 surfaces as a server error so the
// gateway's FailurePolicy can apply. We deliberately do NOT fold
// this into ActionRedact because it indicates a protocol bug at a
// peer, not a filter decision.
func TestEvalPolicy_Filter_BadBase64ReturnsError(t *testing.T) {
	p := newWithClient(testConfig("jira_get_issue"), &stubLLMClient{})

	req := &wire.FilterRequest{
		Scope:      string(wire.ScopeResponse),
		Tool:       "jira_get_issue",
		Headers:    map[string][]string{},
		BodyBase64: "!!! not base64 !!!",
	}
	_, err := p.Filter(context.Background(), req)
	require.Error(t, err)
	require.ErrorContains(t, err, "decode bodyBase64")
}

// TestEvalPolicy_Filter_NilRequestReturnsError guards the public
// API surface.
func TestEvalPolicy_Filter_NilRequestReturnsError(t *testing.T) {
	p := newWithClient(testConfig(), &stubLLMClient{})
	_, err := p.Filter(context.Background(), nil)
	require.Error(t, err)
}

// TestEvalPolicy_Filter_EmptyResultPasses covers a defensive edge:
// a JSON-RPC response with no result field has nothing to filter.
// ActionPass is the correct verdict (and cheap — no LLM call).
func TestEvalPolicy_Filter_EmptyResultPasses(t *testing.T) {
	stub := &stubLLMClient{}
	p := newWithClient(testConfig("jira_get_issue"), stub)

	body := `{"jsonrpc":"2.0","id":1}`
	req := &wire.FilterRequest{
		Scope:      string(wire.ScopeResponse),
		Tool:       "jira_get_issue",
		Headers:    map[string][]string{},
		BodyBase64: base64.StdEncoding.EncodeToString([]byte(body)),
	}
	resp, err := p.Filter(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, string(wire.ActionPass), resp.Action)
	require.Equal(t, 0, stub.calls)
}
