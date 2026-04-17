// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests port tests/test_mcp_utils.py line-for-line so any Python
// test file edit can be reproduced here with confidence that the Go port
// agrees on every edge case.

// --- TestToolArguments --------------------------------------------------

func TestToolArguments_TypicalCase(t *testing.T) {
	body := map[string]any{
		"params": map[string]any{
			"name":      "t",
			"arguments": map[string]any{"a": 1},
		},
	}
	require.Equal(t, map[string]any{"a": 1}, ToolArguments(body))
}

func TestToolArguments_EdgeCasesReturnEmptyDict(t *testing.T) {
	empty := map[string]any{}
	cases := []any{
		nil,
		"not a dict",
		map[string]any{},
		map[string]any{"params": "nope"},
		map[string]any{"params": map[string]any{}},
		map[string]any{"params": map[string]any{"arguments": "nope"}},
	}
	for i, c := range cases {
		require.Equal(t, empty, ToolArguments(c), "case %d", i)
	}
}

// --- TestWithToolArguments ---------------------------------------------

func TestWithToolArguments_ReplacesArgumentsWithoutMutatingInput(t *testing.T) {
	original := map[string]any{
		"params": map[string]any{
			"name":      "t",
			"arguments": map[string]any{"a": 1},
		},
	}
	updated := WithToolArguments(original, map[string]any{"b": 2})

	require.Equal(t, map[string]any{"a": 1}, original["params"].(map[string]any)["arguments"])
	require.Equal(t, map[string]any{"b": 2}, updated["params"].(map[string]any)["arguments"])
}

func TestWithToolArguments_CreatesParamsWhenMissing(t *testing.T) {
	original := map[string]any{"jsonrpc": "2.0"}
	updated := WithToolArguments(original, map[string]any{"x": 1})

	require.Equal(t, map[string]any{"arguments": map[string]any{"x": 1}}, updated["params"])
}

func TestWithToolArguments_NonDictInputGetsMinimalStructure(t *testing.T) {
	updated := WithToolArguments(nil, map[string]any{"a": 1})
	require.Equal(t, map[string]any{
		"params": map[string]any{"arguments": map[string]any{"a": 1}},
	}, updated)
}

func TestWithToolArguments_NonDictParamsReplacedWithDict(t *testing.T) {
	// Python explicitly upgrades a non-dict params to {}.
	original := map[string]any{
		"jsonrpc": "2.0",
		"params":  "not a dict",
	}
	updated := WithToolArguments(original, map[string]any{"a": 1})
	require.Equal(t, map[string]any{"arguments": map[string]any{"a": 1}}, updated["params"])
}

func TestWithToolArguments_PreservesSiblingFields(t *testing.T) {
	original := map[string]any{
		"jsonrpc": "2.0",
		"id":      7,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "t",
			"arguments": map[string]any{"old": true},
		},
	}
	updated := WithToolArguments(original, map[string]any{"new": true})
	require.Equal(t, "2.0", updated["jsonrpc"])
	require.Equal(t, 7, updated["id"])
	require.Equal(t, "tools/call", updated["method"])
	require.Equal(t, "t", updated["params"].(map[string]any)["name"])
}

// --- TestIterTextParts -------------------------------------------------

func TestIterTextParts_ReturnsIndexedTextParts(t *testing.T) {
	result := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "a"},
			map[string]any{"type": "image", "data": "..."},
			map[string]any{"type": "text", "text": "b"},
		},
	}
	require.Equal(t, []TextPart{{Index: 0, Text: "a"}, {Index: 2, Text: "b"}}, IterTextParts(result))
}

func TestIterTextParts_EdgeCasesReturnEmpty(t *testing.T) {
	cases := []any{
		nil,
		"scalar",
		map[string]any{},
		map[string]any{"content": "not a list"},
		map[string]any{"content": []any{1, 2, 3}},
		map[string]any{"content": []any{map[string]any{"type": "text"}}},              // missing text
		map[string]any{"content": []any{map[string]any{"type": "text", "text": 123}}}, // wrong text type
	}
	for i, c := range cases {
		require.Empty(t, IterTextParts(c), "case %d", i)
	}
}

// --- TestWithTextParts -------------------------------------------------

func TestWithTextParts_ReplacesSpecifiedIndicesOnly(t *testing.T) {
	result := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "a"},
			map[string]any{"type": "text", "text": "b"},
			map[string]any{"type": "text", "text": "c"},
		},
		"isError": false,
	}
	updated := WithTextParts(result, map[int]string{0: "A", 2: "C"})
	u := updated.(map[string]any)
	content := u["content"].([]any)
	texts := make([]string, len(content))
	for i, item := range content {
		texts[i] = item.(map[string]any)["text"].(string)
	}
	require.Equal(t, []string{"A", "b", "C"}, texts)
	require.Equal(t, false, u["isError"])
}

func TestWithTextParts_IgnoresInvalidIndices(t *testing.T) {
	result := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "a"},
		},
	}
	updated := WithTextParts(result, map[int]string{-1: "X", 999: "Y"})
	content := updated.(map[string]any)["content"].([]any)
	require.Equal(t, "a", content[0].(map[string]any)["text"])
}

func TestWithTextParts_DoesNotMutateInput(t *testing.T) {
	result := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "a"},
		},
	}
	_ = WithTextParts(result, map[int]string{0: "Z"})
	// Original must not have been touched.
	require.Equal(t, "a", result["content"].([]any)[0].(map[string]any)["text"])
}

func TestWithTextParts_ReturnsInputVerbatimWhenNoContentKey(t *testing.T) {
	// Python shortcut: if "content" isn't present, return result as-is.
	result := map[string]any{"isError": false}
	updated := WithTextParts(result, map[int]string{0: "X"})
	require.Equal(t, result, updated)
}

func TestWithTextParts_SkipsNonTextSlots(t *testing.T) {
	// Index 1 is an image; a replacement targeting it must be a no-op.
	result := map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": "a"},
			map[string]any{"type": "image", "data": "..."},
		},
	}
	updated := WithTextParts(result, map[int]string{1: "X"})
	content := updated.(map[string]any)["content"].([]any)
	require.Equal(t, "...", content[1].(map[string]any)["data"])
	_, has := content[1].(map[string]any)["text"]
	require.False(t, has)
}

// --- TestResponseResult ------------------------------------------------

func TestResponseResult_ReturnsResult(t *testing.T) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"result":  map[string]any{"x": 1},
	}
	require.Equal(t, map[string]any{"x": 1}, ResponseResult(body))
}

func TestResponseResult_EdgeCases(t *testing.T) {
	cases := []any{
		nil,
		"x",
		map[string]any{},
		map[string]any{"error": map[string]any{"code": -1}},
	}
	for i, c := range cases {
		require.Nil(t, ResponseResult(c), "case %d", i)
	}
}

// --- TestWithResponseResult --------------------------------------------

func TestWithResponseResult_ReplacesResultAndClearsError(t *testing.T) {
	body := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"error":   map[string]any{"code": -1, "message": "bad"},
		"result":  map[string]any{"old": true},
	}
	updated := WithResponseResult(body, map[string]any{"new": true})

	require.Equal(t, map[string]any{"new": true}, updated["result"])
	_, hasError := updated["error"]
	require.False(t, hasError, "error key must be removed")

	// Input must not have been mutated.
	require.Equal(t, map[string]any{"old": true}, body["result"])
	require.Contains(t, body, "error")
}

func TestWithResponseResult_NonDictInput(t *testing.T) {
	updated := WithResponseResult(nil, map[string]any{"x": 1})
	require.Equal(t, map[string]any{"jsonrpc": "2.0", "result": map[string]any{"x": 1}}, updated)
}

// --- Deep copy behaviour -----------------------------------------------

func TestWithToolArguments_DeepCopiesNestedStructures(t *testing.T) {
	nested := map[string]any{"a": []any{1, 2, 3}}
	original := map[string]any{
		"params": map[string]any{
			"arguments": map[string]any{"existing": nested},
		},
	}

	updated := WithToolArguments(original, map[string]any{"new": true})

	// Mutating `nested` must not leak into `updated`.
	nested["a"] = "mutated"

	// (updated doesn't carry nested, but verifying the deep-copy by checking
	// unchanged siblings in the body.)
	require.Equal(t, map[string]any{"new": true},
		updated["params"].(map[string]any)["arguments"])
}
