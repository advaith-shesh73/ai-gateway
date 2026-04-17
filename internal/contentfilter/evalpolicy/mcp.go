// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"bytes"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// mcpWrapper captures the shape of an MCP tool-call result so we can
// unwrap the inner text, run it through the LLM, and rewrap without
// disturbing the envelope. Fields use json.RawMessage for everything
// we don't touch — this preserves byte-level fidelity of the
// surrounding structure (field order inside objects is NOT preserved
// by the Go JSON encoder, but sibling fields keep their values).
type mcpWrapper struct {
	Content []mcpContentItem `json:"content"`
	// extras holds every wrapper-level field we didn't name above
	// (isError, _meta, etc.) so rebuildMCPOutput can carry them
	// through to the response verbatim. Populated by
	// parseMCPOutput via a second unmarshal into a map.
	extras map[string]json.RawMessage
}

// mcpContentItem is a single entry in the content array. We only
// care about "text" items (they carry JSON-stringified tool output);
// other types (image, resource, etc.) are left alone.
type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
	// raw stashes the full JSON of this item so rebuildMCPOutput
	// can emit non-text items unchanged.
	raw json.RawMessage
}

// parseMCPOutput inspects raw and, if it matches the MCP wrapper
// shape, returns (innerText, wrapper) where innerText is the LLM's
// input. Otherwise returns (raw, nil) and the caller sends raw
// straight to the LLM.
//
// Ported from PR 95's parse_mcp_output. Two shapes are supported:
//
//  1. Simple JSON/plain: raw is returned as-is with nil wrapper.
//  2. Nested MCP: raw decodes to {"content":[{"type":"text",
//     "text":"..."}, ...], ...}. The first text item's value is
//     returned as innerText; the wrapper carries the rest of the
//     structure for later rebuild.
//
// The function never returns an error: invalid JSON, absent content
// arrays, and content arrays with no text items ALL fall through to
// the "simple" case so the LLM sees the raw bytes.
func parseMCPOutput(raw string) (string, *mcpWrapper) {
	if raw == "" {
		return raw, nil
	}
	// First decode: extract the content array. We do this with a
	// loose RawMessage walk so unrelated fields are preserved
	// byte-for-byte.
	var top map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &top); err != nil {
		return raw, nil
	}
	contentRaw, ok := top["content"]
	if !ok {
		return raw, nil
	}
	var items []json.RawMessage
	if err := json.Unmarshal(contentRaw, &items); err != nil {
		return raw, nil
	}
	if len(items) == 0 {
		return raw, nil
	}

	parsedItems := make([]mcpContentItem, 0, len(items))
	firstTextIdx := -1
	for i, it := range items {
		var decoded mcpContentItem
		if err := json.Unmarshal(it, &decoded); err != nil {
			// Preserve as an opaque non-text item.
			parsedItems = append(parsedItems, mcpContentItem{raw: it})
			continue
		}
		decoded.raw = it
		if decoded.Type == "text" && firstTextIdx == -1 {
			firstTextIdx = i
		}
		parsedItems = append(parsedItems, decoded)
	}
	if firstTextIdx == -1 {
		return raw, nil
	}

	extras := make(map[string]json.RawMessage, len(top))
	for k, v := range top {
		if k == "content" {
			continue
		}
		extras[k] = v
	}
	w := &mcpWrapper{Content: parsedItems, extras: extras}
	return parsedItems[firstTextIdx].Text, w
}

// rebuildMCPOutput rewraps filtered into wrapper. When wrapper is
// nil it returns filtered directly (the simple-JSON/plain-text
// case). Otherwise only the first text item is replaced with
// filtered; all other wrapper fields and non-text content items are
// emitted unchanged.
//
// Ported from PR 95's rebuild_mcp_output. We deliberately do NOT
// mutate wrapper — callers may share it across goroutines in the
// future, and the original PR 95 test asserts deep-copy semantics.
func rebuildMCPOutput(filtered string, wrapper *mcpWrapper) (string, error) {
	if wrapper == nil {
		return filtered, nil
	}

	out := map[string]json.RawMessage{}
	for k, v := range wrapper.extras {
		out[k] = v
	}

	contentOut := make([]json.RawMessage, 0, len(wrapper.Content))
	replaced := false
	for _, item := range wrapper.Content {
		if !replaced && item.Type == "text" {
			rebuilt, err := json.Marshal(struct {
				Type string `json:"type"`
				Text string `json:"text"`
			}{Type: "text", Text: filtered})
			if err != nil {
				return "", err
			}
			contentOut = append(contentOut, rebuilt)
			replaced = true
			continue
		}
		if len(item.raw) > 0 {
			contentOut = append(contentOut, item.raw)
		}
	}

	contentBytes, err := json.Marshal(contentOut)
	if err != nil {
		return "", err
	}
	out["content"] = contentBytes

	// Encoding via a deterministic buffer keeps the output
	// stable across Go versions — tests assert on exact bytes.
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(out); err != nil {
		return "", err
	}
	// json.Encoder.Encode appends a newline; strip it so the
	// wrapper looks like json.Marshal's output.
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}
