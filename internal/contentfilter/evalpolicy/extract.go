// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"regexp"
	"strings"
)

// thinkBlockRE matches <think>...</think> blocks produced by
// reasoning-capable models (e.g. hack-reason) that wrap their
// chain-of-thought in explicit tags. We strip them before taking the
// model's answer because they carry reasoning over the redacted
// content and would themselves constitute a leak.
//
// The `(?s)` flag lets . span newlines. Non-greedy `.*?` so two
// consecutive think blocks are handled independently.
var thinkBlockRE = regexp.MustCompile(`(?s)<think>.*?</think>`)

// extractFilteredText strips wrapper artefacts from a raw LLM
// response and returns the redacted content the policy should emit.
// Two transformations are applied, in order:
//
//  1. Remove every <think>...</think> block (including newlines).
//  2. If what remains starts with a markdown fence (```json or
//     ```), strip the fence and its closing counterpart.
//
// Ported from PR 95's extract_filtered_text. The stripping logic is
// conservative: if the response is clean already, it is returned
// unchanged (modulo surrounding whitespace).
func extractFilteredText(rawLLMResponse string) string {
	text := thinkBlockRE.ReplaceAllString(rawLLMResponse, "")
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "```") {
		return text
	}
	// Drop the opening fence line.
	lines := strings.Split(text, "\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "```") {
		lines = lines[1:]
	}
	// Drop the closing fence line if it's there (the Python
	// implementation tolerates its absence — we do the same).
	if n := len(lines); n > 0 && strings.HasPrefix(strings.TrimSpace(lines[n-1]), "```") {
		lines = lines[:n-1]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}
