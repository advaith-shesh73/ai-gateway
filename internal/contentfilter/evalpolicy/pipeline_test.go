// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubLLMClient is a test double for the llmClient interface. It
// lets tests assert on the prompt pair the pipeline actually
// produces and inject canned responses (or errors) in return.
type stubLLMClient struct {
	// response is returned on Complete unless err is set.
	response string
	// err, if non-nil, is returned instead of response. Mirrors a
	// real-world LLM outage.
	err error
	// capturedSystem is the system prompt from the last call.
	capturedSystem string
	// capturedUser is the user prompt from the last call.
	capturedUser string
	// calls counts how many times Complete was invoked.
	calls int
}

func (s *stubLLMClient) Complete(_ context.Context, systemPrompt, userPrompt string) (string, error) {
	s.calls++
	s.capturedSystem = systemPrompt
	s.capturedUser = userPrompt
	if s.err != nil {
		return "", s.err
	}
	return s.response, nil
}

// TestFilterToolOutput_JiraWithWrapper ports PR 95's
// test_jira_filtering_with_wrapper. Validates the full happy-path:
// parse MCP wrapper, send inner text to LLM, extract, rebuild wrapper.
func TestFilterToolOutput_JiraWithWrapper(t *testing.T) {
	filteredInner := fmt.Sprintf(
		`{"summary":"Cluster failure","root_cause":"%s","resolution":"%s","priority":"P1"}`,
		redactedMarker, redactedMarker,
	)
	stub := &stubLLMClient{response: filteredInner}

	inner := `{"summary":"Cluster failure","root_cause":"Disk failure on node A","resolution":"Replaced disk","priority":"P1"}`
	raw := fmt.Sprintf(`{"content":[{"type":"text","text":%q}],"isError":false}`, inner)

	out, err := filterToolOutput(context.Background(), stub, "jira_get_issue", "ENG-885568", raw)
	require.NoError(t, err)

	// Out is the re-wrapped MCP body; decode and peek at content[0].text.
	_, wrapper := parseMCPOutput(out)
	require.NotNil(t, wrapper)
	require.Len(t, wrapper.Content, 1)
	require.Equal(t, filteredInner, wrapper.Content[0].Text)

	// Prompt must have included the inner text and tool name.
	require.Contains(t, stub.capturedUser, "jira_get_issue")
	require.Contains(t, stub.capturedUser, inner)
	require.Equal(t, systemPrompt, stub.capturedSystem)
}

// TestFilterToolOutput_SimpleJSONWithoutWrapper mirrors PR 95's
// test_simple_json_without_wrapper.
func TestFilterToolOutput_SimpleJSONWithoutWrapper(t *testing.T) {
	stub := &stubLLMClient{response: `{"filtered":true}`}

	out, err := filterToolOutput(context.Background(), stub, "get_runbook", "ENG-1",
		`{"content":"some runbook"}`)
	require.NoError(t, err)
	require.Contains(t, out, `"filtered":true`)
}

// TestFilterToolOutput_ThinkBlocks_Stripped mirrors PR 95's
// test_llm_returns_think_blocks. Asserts <think> content never
// survives into the output.
func TestFilterToolOutput_ThinkBlocks_Stripped(t *testing.T) {
	stub := &stubLLMClient{response: "<think>analyzing content...</think>\n{\"clean\": true}"}

	out, err := filterToolOutput(context.Background(), stub, "jira_get_issue", "ENG-1",
		`{"dirty":true}`)
	require.NoError(t, err)
	require.Contains(t, out, `"clean": true`)
	require.NotContains(t, out, "<think>")
}

// TestFilterToolOutput_MarkdownFences_Stripped mirrors PR 95's
// test_llm_returns_markdown_fenced_json.
func TestFilterToolOutput_MarkdownFences_Stripped(t *testing.T) {
	stub := &stubLLMClient{response: "```json\n{\"clean\": true}\n```"}

	out, err := filterToolOutput(context.Background(), stub, "jira_get_issue", "ENG-1",
		`{"dirty":true}`)
	require.NoError(t, err)
	require.Contains(t, out, `"clean": true`)
	require.NotContains(t, out, "```")
}

// TestFilterToolOutput_LLMFailure_Propagates mirrors PR 95's
// test_llm_exception_propagates. The pipeline itself surfaces the
// error; safe-redaction is the caller's responsibility (in
// gateway-land, Policy.Filter).
func TestFilterToolOutput_LLMFailure_Propagates(t *testing.T) {
	stub := &stubLLMClient{err: errors.New("LLM unreachable")}

	_, err := filterToolOutput(context.Background(), stub, "jira_get_issue", "ENG-1",
		`{"data":"test"}`)
	require.ErrorContains(t, err, "LLM unreachable")
}

// TestFilterToolOutput_PlainTextPassthrough mirrors PR 95's
// test_plain_text_input.
func TestFilterToolOutput_PlainTextPassthrough(t *testing.T) {
	stub := &stubLLMClient{response: "filtered plain text"}

	out, err := filterToolOutput(context.Background(), stub, "query_knowledge", "ENG-1",
		"raw plain text")
	require.NoError(t, err)
	require.Equal(t, "filtered plain text", out)
}

// TestFilterToolOutput_SelfReferenceRemovalInArray ports PR 95's
// test_supportgpt_filtering shape: the LLM is trusted to remove the
// array entry containing the excluded ticket id; the pipeline just
// plumbs the filtered JSON through.
func TestFilterToolOutput_SelfReferenceRemovalInArray(t *testing.T) {
	filtered := `{"similar_rcas":[{"rca_id":"RCA-001","title":"Unrelated"}],"confidence":0.9}`
	stub := &stubLLMClient{response: filtered}

	inner := `{"similar_rcas":[{"rca_id":"RCA-001","title":"Unrelated"},{"rca_id":"ENG-885568","title":"Self reference"}],"confidence":0.9}`

	out, err := filterToolOutput(context.Background(), stub, "find_similar_rcas", "ENG-885568", inner)
	require.NoError(t, err)
	require.Equal(t, filtered, out)
}
