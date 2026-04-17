// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// TestParseMCPOutput covers every shape PR 95's test_eval_filter_hook.py
// exercises under TestMCPOutputParsing, plus one Go-specific case
// (array-typed top-level). The Python reference tests are at
// panacea-agent#95 tests/test_eval_filter_hook.py::TestMCPOutputParsing.
func TestParseMCPOutput(t *testing.T) {
	t.Run("simple JSON without content field returns raw and nil wrapper", func(t *testing.T) {
		raw := `{"summary": "test"}`
		inner, w := parseMCPOutput(raw)
		require.Equal(t, raw, inner)
		require.Nil(t, w)
	})

	t.Run("nested MCP format extracts inner text and retains wrapper", func(t *testing.T) {
		innerJSON := `{"summary":"test","resolution":"Fixed"}`
		raw, err := json.Marshal(map[string]any{
			"content": []any{map[string]any{"type": "text", "text": innerJSON}},
			"isError": false,
		})
		require.NoError(t, err)

		inner, w := parseMCPOutput(string(raw))
		require.JSONEq(t, innerJSON, inner)
		require.NotNil(t, w)
		require.JSONEq(t, `false`, string(w.extras["isError"]))
	})

	t.Run("invalid JSON returns raw and nil wrapper", func(t *testing.T) {
		inner, w := parseMCPOutput("not json at all")
		require.Equal(t, "not json at all", inner)
		require.Nil(t, w)
	})

	t.Run("empty string returns raw and nil wrapper", func(t *testing.T) {
		inner, w := parseMCPOutput("")
		require.Empty(t, inner)
		require.Nil(t, w)
	})

	t.Run("JSON without content key passes through", func(t *testing.T) {
		raw := `{"data":[1,2,3]}`
		inner, w := parseMCPOutput(raw)
		require.Equal(t, raw, inner)
		require.Nil(t, w)
	})

	t.Run("content with only non-text items passes through", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"content": []any{map[string]any{"type": "image", "url": "http://x"}},
		})
		require.NoError(t, err)
		inner, w := parseMCPOutput(string(raw))
		require.Equal(t, string(raw), inner)
		require.Nil(t, w)
	})

	t.Run("content with mixed items returns first text item", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"content": []any{
				map[string]any{"type": "image", "url": "http://x"},
				map[string]any{"type": "text", "text": "hello"},
				map[string]any{"type": "text", "text": "ignored"},
			},
		})
		require.NoError(t, err)
		inner, w := parseMCPOutput(string(raw))
		require.Equal(t, "hello", inner)
		require.NotNil(t, w)
	})

	t.Run("top-level JSON array falls through", func(t *testing.T) {
		inner, w := parseMCPOutput(`[1,2,3]`)
		require.Equal(t, `[1,2,3]`, inner)
		require.Nil(t, w)
	})
}

// TestRebuildMCPOutput covers every assertion from PR 95's
// TestMCPOutputRebuilding. The deep-copy assertion is enforced by
// "does not mutate original wrapper": if rebuildMCPOutput shared
// state with the input, re-parsing the second time would see the
// mutated text.
func TestRebuildMCPOutput(t *testing.T) {
	t.Run("no wrapper returns filtered text directly", func(t *testing.T) {
		got, err := rebuildMCPOutput("filtered text", nil)
		require.NoError(t, err)
		require.Equal(t, "filtered text", got)
	})

	t.Run("with wrapper preserves structure and replaces text", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "original"}},
			"isError": false,
		})
		require.NoError(t, err)
		_, w := parseMCPOutput(string(raw))
		require.NotNil(t, w)

		got, err := rebuildMCPOutput("filtered", w)
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(got), &decoded))
		require.Equal(t, false, decoded["isError"])
		require.Equal(t, "filtered",
			decoded["content"].([]any)[0].(map[string]any)["text"])
	})

	t.Run("preserves extra wrapper fields", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "old"}},
			"isError": false,
			"_meta":   map[string]any{"server": "jira"},
		})
		require.NoError(t, err)
		_, w := parseMCPOutput(string(raw))
		require.NotNil(t, w)

		got, err := rebuildMCPOutput("new", w)
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(got), &decoded))
		require.Equal(t, "jira",
			decoded["_meta"].(map[string]any)["server"])
	})

	t.Run("preserves non-text content items alongside replaced text", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"content": []any{
				map[string]any{"type": "image", "url": "http://x"},
				map[string]any{"type": "text", "text": "replace me"},
			},
		})
		require.NoError(t, err)
		_, w := parseMCPOutput(string(raw))
		require.NotNil(t, w)

		got, err := rebuildMCPOutput("replaced", w)
		require.NoError(t, err)
		var decoded map[string]any
		require.NoError(t, json.Unmarshal([]byte(got), &decoded))
		items := decoded["content"].([]any)
		require.Len(t, items, 2)
		require.Equal(t, "image", items[0].(map[string]any)["type"])
		require.Equal(t, "http://x", items[0].(map[string]any)["url"])
		require.Equal(t, "text", items[1].(map[string]any)["type"])
		require.Equal(t, "replaced", items[1].(map[string]any)["text"])
	})

	t.Run("does not mutate the input wrapper", func(t *testing.T) {
		raw, err := json.Marshal(map[string]any{
			"content": []any{map[string]any{"type": "text", "text": "original"}},
		})
		require.NoError(t, err)
		_, w := parseMCPOutput(string(raw))
		require.NotNil(t, w)
		originalText := w.Content[0].Text

		_, err = rebuildMCPOutput("changed", w)
		require.NoError(t, err)
		require.Equal(t, originalText, w.Content[0].Text,
			"rebuild must not mutate the wrapper's text in-place")
	})
}
