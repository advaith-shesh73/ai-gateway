// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBuildUserPrompt mirrors PR 95's TestPromptConstruction. It
// asserts the stable properties of the template that the evaluation
// benchmarks depend on: tool name, ticket id, and content appear in
// the prompt, and so do every resolution-named field from the PR 95
// list. Any change to these would invalidate existing benchmarks —
// tests guard the template against drift.
func TestBuildUserPrompt(t *testing.T) {
	t.Run("includes tool name", func(t *testing.T) {
		got := buildUserPrompt("MCP:jira_get_issue", "ENG-123", "test")
		require.Contains(t, got, "MCP:jira_get_issue")
	})

	t.Run("includes ticket id", func(t *testing.T) {
		got := buildUserPrompt("MCP:jira_get_issue", "ENG-885568", "{}")
		require.Contains(t, got, "ENG-885568")
	})

	t.Run("includes content", func(t *testing.T) {
		content := `{"summary":"cluster failure","root_cause":"disk"}`
		got := buildUserPrompt("MCP:jira_get_issue", "ENG-1", content)
		require.Contains(t, got, content)
	})

	t.Run("includes redaction marker", func(t *testing.T) {
		got := buildUserPrompt("T", "X", "Y")
		require.Contains(t, got, "[REDACTED FOR EVALUATION]")
	})

	t.Run("instructs to err on side of redacting", func(t *testing.T) {
		got := buildUserPrompt("T", "X", "Y")
		require.Contains(t, got, "Over-filtering is acceptable")
	})

	t.Run("lists all PR 95 resolution-named fields", func(t *testing.T) {
		got := buildUserPrompt("T", "X", "Y")
		for _, field := range []string{
			"root_cause", "resolution", "workaround", "remediation",
			"fix_version", "corrective_action", "relief_provided",
		} {
			require.Contains(t, got, field,
				"resolution-named field %q must appear in the prompt", field)
		}
	})

	t.Run("ticket id appears exactly three times", func(t *testing.T) {
		got := buildUserPrompt("T", "ENG-UNIQUE-42", "Y")
		require.Equal(t, 3, strings.Count(got, "ENG-UNIQUE-42"),
			"PR 95 template references ticket_id at EVALUATION TICKET, self-references, and array removal — %s format string verb count must match",
			"tc")
	})
}

// TestSystemPrompt asserts the stable properties of the system
// prompt. Again: the prose is the product of the filter, any change
// here requires coordination with the evaluation methodology.
func TestSystemPrompt(t *testing.T) {
	require.Contains(t, systemPrompt, "data leakage")
	require.Contains(t, systemPrompt, "resolution and root cause")
	require.Contains(t, systemPrompt, "No explanations")
}
