// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"context"
	"fmt"
)

// buildUserPrompt materialises [userPromptTemplate] with the
// per-call values substituted in. Extracted so tests can assert
// prompt construction without running the pipeline.
//
// The template carries five %s verbs in this order:
//
//	tool_name, ticket_id, ticket_id, ticket_id, content
//
// (see [userPromptTemplate]). Any reshuffle requires a matching test
// update in prompts_test.go.
func buildUserPrompt(toolName, ticketID, content string) string {
	return fmt.Sprintf(userPromptTemplate, toolName, ticketID, ticketID, ticketID, content)
}

// filterToolOutput is the core PR 95 pipeline: parse → LLM →
// extract → rebuild. Separated from [EvalPolicy.Filter] so tests can
// swap in a fake llmClient without constructing a whole policy.
//
// The function preserves PR 95's behaviour on two edge cases:
//
//   - Empty wrapper + empty extracted LLM output: we still return
//     the empty string (rather than defaulting to the unavailable
//     sentinel). PR 95 returned "" here and downstream tests assert
//     on that shape.
//   - LLM error: we return the error unmodified so the caller can
//     choose whether to fall back to [filterUnavailableText] or to
//     surface the error (Policy.Filter picks the former;
//     fuzz/bench tests may prefer the raw error).
func filterToolOutput(
	ctx context.Context,
	client llmClient,
	toolName, ticketID, toolOutputRaw string,
) (string, error) {
	innerText, wrapper := parseMCPOutput(toolOutputRaw)
	prompt := buildUserPrompt(toolName, ticketID, innerText)
	raw, err := client.Complete(ctx, systemPrompt, prompt)
	if err != nil {
		return "", err
	}
	filtered := extractFilteredText(raw)
	return rebuildMCPOutput(filtered, wrapper)
}
