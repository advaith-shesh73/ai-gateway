// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExtractFilteredText mirrors PR 95's TestExtractFilteredText
// (Python reference) one-for-one. Each sub-test corresponds to a
// Python test method of the same shape.
func TestExtractFilteredText(t *testing.T) {
	tt := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "clean_json_output",
			in:   `{"key": "value"}`,
			want: `{"key": "value"}`,
		},
		{
			name: "strips_think_blocks",
			in:   "<think>Let me analyze this carefully...</think>\n{\"key\": \"value\"}",
			want: `{"key": "value"}`,
		},
		{
			name: "strips_multiline_think_blocks",
			in:   "<think>\nstep 1\nstep 2\nstep 3\n</think>\nresult text",
			want: "result text",
		},
		{
			name: "strips_markdown_json_fences",
			in:   "```json\n{\"key\": \"value\"}\n```",
			want: `{"key": "value"}`,
		},
		{
			name: "strips_plain_fences",
			in:   "```\n{\"key\": \"value\"}\n```",
			want: `{"key": "value"}`,
		},
		{
			name: "strips_think_and_fences_combined",
			in:   "<think>reasoning</think>\n```json\n{\"clean\": true}\n```",
			want: `{"clean": true}`,
		},
		{
			name: "empty_input_returns_empty",
			in:   "",
			want: "",
		},
		{
			name: "preserves_multiline_content",
			in:   "{\"line1\": \"a\",\n\"line2\": \"b\"}",
			want: "{\"line1\": \"a\",\n\"line2\": \"b\"}",
		},
		{
			name: "only_think_block_returns_empty",
			in:   "<think>just thinking</think>",
			want: "",
		},
		{
			name: "two_consecutive_think_blocks_both_stripped",
			in:   "<think>first</think><think>second</think>keep",
			want: "keep",
		},
		{
			name: "unclosed_fence_without_closer_still_works",
			in:   "```json\n{\"k\":1}",
			want: `{"k":1}`,
		},
	}

	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, extractFilteredText(tc.in))
		})
	}
}
