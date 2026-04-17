// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// MCP JSON-RPC helpers — parity reference is
// panacea-agent/services/aigw-content-filter/app/mcp_utils.py.
//
// The Python helpers operate on untyped dicts because JSON-RPC payloads
// routinely carry oddities (missing keys, wrong types) and handlers must
// cope uniformly. The Go port follows the same contract: every helper
// accepts `any` (typically a value freshly `json.Unmarshal`ed into
// `map[string]any`) and returns either the extracted value or a safe
// fallback.
//
// All mutation helpers deep-copy their input so callers never need to
// defensively copy. This matches the Python semantic (`copy.deepcopy`)
// and is why handlers can safely hand the mutated body off to another
// helper without worrying about shared state bugs.

// ToolArguments returns `params.arguments` as a `map[string]any` (possibly
// empty). Any malformed shape — non-dict request, missing `params`,
// non-dict params, missing or non-dict `arguments` — collapses to an empty
// map so callers can uniformly `args["key"]` without defensive branches.
//
// NOTE: the returned map is an alias into the caller's input. Do NOT
// mutate it in place; use [WithToolArguments] to obtain a modified copy.
func ToolArguments(requestBody any) map[string]any {
	empty := map[string]any{}
	body, ok := requestBody.(map[string]any)
	if !ok {
		return empty
	}
	params, ok := body["params"].(map[string]any)
	if !ok {
		return empty
	}
	args, ok := params["arguments"].(map[string]any)
	if !ok {
		return empty
	}
	return args
}

// WithToolArguments deep-copies `requestBody` and replaces
// `params.arguments` with `newArgs`. The return value is always a
// `map[string]any`; non-dict input is upgraded to the minimal shape
// `{"params": {"arguments": newArgs}}` — this mirrors the Python fallback
// path, which exists so handlers never have to special-case a malformed
// inbound request.
//
// `newArgs` is shallow-copied into the returned body (parity with
// `dict(new_args)` in Python). If callers need deep semantics on
// nested args they must deep-copy prior to calling.
func WithToolArguments(requestBody any, newArgs map[string]any) map[string]any {
	argsCopy := make(map[string]any, len(newArgs))
	for k, v := range newArgs {
		argsCopy[k] = v
	}

	body, ok := requestBody.(map[string]any)
	if !ok {
		return map[string]any{
			"params": map[string]any{"arguments": argsCopy},
		}
	}

	out := deepCopyJSON(body).(map[string]any)
	params, ok := out["params"].(map[string]any)
	if !ok {
		params = map[string]any{}
		out["params"] = params
	}
	params["arguments"] = argsCopy
	return out
}

// TextPart is one (index, text) pair from a JSON-RPC `result.content`
// array. The index is preserved so callers can write a replacement back
// into the same slot via [WithTextParts] without ambiguity in the face of
// non-text items (images, audio, etc.).
type TextPart struct {
	Index int
	Text  string
}

// IterTextParts returns every `content[i]` whose `type` is exactly
// `"text"` and whose `text` field is a string. Non-text items (images,
// resources, malformed entries) are skipped — their indices are not
// emitted, but they still occupy positions in the caller's backing
// array so [WithTextParts] can write replacements by index.
func IterTextParts(result any) []TextPart {
	r, ok := result.(map[string]any)
	if !ok {
		return nil
	}
	content, ok := r["content"].([]any)
	if !ok {
		return nil
	}
	var out []TextPart
	for i, item := range content {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if t, _ := m["type"].(string); t != "text" {
			continue
		}
		text, ok := m["text"].(string)
		if !ok {
			continue
		}
		out = append(out, TextPart{Index: i, Text: text})
	}
	return out
}

// WithTextParts deep-copies `result` and replaces `content[i].text`
// entries according to `replacements`. Keys that don't correspond to an
// existing text part (negative index, out-of-range, non-text item at that
// index) are silently ignored — this matches the Python behaviour and
// keeps the helper robust against index drift from upstream shape
// changes.
//
// If `result` is not a dict or is missing a `content` key, it is
// returned verbatim. Callers that need unconditional deep-copy semantics
// should wrap the call site accordingly.
func WithTextParts(result any, replacements map[int]string) any {
	r, ok := result.(map[string]any)
	if !ok {
		return result
	}
	if _, hasContent := r["content"]; !hasContent {
		return result
	}
	out := deepCopyJSON(r).(map[string]any)
	content, ok := out["content"].([]any)
	if !ok {
		return out
	}
	for idx, newText := range replacements {
		if idx < 0 || idx >= len(content) {
			continue
		}
		item, ok := content[idx].(map[string]any)
		if !ok {
			continue
		}
		if t, _ := item["type"].(string); t != "text" {
			continue
		}
		item["text"] = newText
	}
	return out
}

// ResponseResult returns `response_body.result` or nil when missing, not
// a dict, or the field is absent. Callers compare the return value with
// `nil` (not `== any(nil)`) — Go's typed nil trap does not apply because
// we return a bare `any`.
func ResponseResult(responseBody any) any {
	body, ok := responseBody.(map[string]any)
	if !ok {
		return nil
	}
	return body["result"]
}

// WithResponseResult deep-copies `response_body`, sets `result` to
// `newResult`, and removes any `error` key that was present — an error
// and a successful result are mutually exclusive under JSON-RPC and the
// ported Python code is explicit that replacing the result implies the
// error is stale.
//
// Non-dict input is upgraded to `{"jsonrpc": "2.0", "result": newResult}`
// to match the Python fallback path.
func WithResponseResult(responseBody any, newResult any) map[string]any {
	body, ok := responseBody.(map[string]any)
	if !ok {
		return map[string]any{
			"jsonrpc": "2.0",
			"result":  newResult,
		}
	}
	out := deepCopyJSON(body).(map[string]any)
	out["result"] = newResult
	delete(out, "error")
	return out
}

// deepCopyJSON recursively clones a value that was produced by
// `json.Unmarshal` into `any` (so its components are one of
// map[string]any, []any, string, float64, bool, nil). Anything else is
// returned as-is — this matches Python's `copy.deepcopy` semantic for
// primitive types while avoiding reflection for hot paths.
func deepCopyJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = deepCopyJSON(vv)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = deepCopyJSON(vv)
		}
		return out
	default:
		return v
	}
}

// splitForPII splits `text` into `<= maxChars` chunks, preferring
// paragraph (`"\n\n"`) breaks, then line (`"\n"`) breaks, then hard-
// slicing at the rune boundary. Parity reference:
// panacea-agent/services/aigw-content-filter/app/pii_client.py:_split_for_pii.
//
// Invariants (all load-bearing — see HANDOFF_GO_PORT_REFERENCE §7.7.4):
//
//   - Length is measured in runes, not bytes. Multi-byte CJK text with
//     byte length > maxChars but rune count ≤ maxChars emits a single
//     chunk.
//   - No chunk boundary ever lands inside a UTF-8 code point.
//   - Boundary-only inputs (e.g. `"\n\n\n\n"`) never panic.
//   - At least one chunk is always emitted for non-empty input; empty
//     input returns an empty slice.
//   - `maxChars <= 0` is treated as "no splitting" and returns
//     `[]string{text}` verbatim.
func splitForPII(text string, maxChars int) []string {
	if maxChars <= 0 {
		return []string{text}
	}
	runes := []rune(text)
	n := len(runes)
	if n == 0 {
		return []string{}
	}

	out := make([]string, 0, 1+n/maxChars)
	i := 0
	for i < n {
		end := i + maxChars
		if end > n {
			end = n
		}
		if end < n {
			breakAt := lastDoubleNewlineRune(runes, i, end)
			if breakAt == -1 || breakAt <= i {
				breakAt = lastNewlineRune(runes, i, end)
			}
			if breakAt != -1 && breakAt > i {
				end = breakAt
			}
		}
		out = append(out, string(runes[i:end]))
		i = end
	}
	return out
}

// lastDoubleNewlineRune returns the largest k in [start, end-1) with
// runes[k]=='\n' && runes[k+1]=='\n', or -1 if no such k exists. The
// signature matches Python `str.rfind("\n\n", start, end)` semantics:
// `end` is exclusive and the match must fit entirely within the window.
func lastDoubleNewlineRune(runes []rune, start, end int) int {
	for k := end - 2; k >= start; k-- {
		if runes[k] == '\n' && runes[k+1] == '\n' {
			return k
		}
	}
	return -1
}

// lastNewlineRune returns the largest k in [start, end) with
// runes[k]=='\n', or -1 if no such k exists. Matches Python
// `str.rfind("\n", start, end)`.
func lastNewlineRune(runes []rune, start, end int) int {
	for k := end - 1; k >= start; k-- {
		if runes[k] == '\n' {
			return k
		}
	}
	return -1
}
