// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Tests for the redaction audit-log primitive kept on the gateway
// side. PII-client integration tests (fail-open vs fail-closed
// emissions) live with the external filter service now — see
// panacea-agent/services/aigw-content-filter-dispatcher.
//
// Scope of coverage here is limited to:
//   * SlogRedactionAuditLogger emits JSON with the expected fields
//     through a caller-supplied handler.
//   * A nil-handler logger is safe (never panics).
//
// The audit logger is also indirectly exercised by the shadow-mode
// tests via emitShadowAudit.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// TestSlogRedactionAuditLogger_WritesThroughCallerHandler checks that
// the logger writes a "redaction" JSON record through the supplied
// handler with the documented field set.
func TestSlogRedactionAuditLogger_WritesThroughCallerHandler(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	audit := NewSlogRedactionAuditLogger(slog.New(h))

	audit.LogRedaction(context.Background(), &RedactionAuditEvent{
		Timestamp:   time.Unix(1700000000, 0).UTC(),
		Route:       "r1",
		Backend:     "b1",
		Tool:        "t1",
		PIIContext:  "pii_scan:unit",
		InputChars:  12,
		OutputChars: 5,
		Stats:       map[string]int{"EMAIL": 2},
		Elapsed:     42 * time.Millisecond,
		Outcome:     "ok",
		FailOpen:    false,
	})

	var got map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &got); err != nil {
		t.Fatalf("audit output is not valid JSON: %v\n---\n%s", err, buf.String())
	}
	if got["msg"] != "redaction" {
		t.Fatalf("expected msg=redaction, got %q", got["msg"])
	}
	for _, key := range []string{"route", "backend", "tool", "pii_context", "input_chars", "output_chars", "outcome", "fail_open", "stats"} {
		if _, ok := got[key]; !ok {
			t.Fatalf("audit record missing key %q; got %v", key, got)
		}
	}
	if got["fail_open"] != false {
		t.Fatalf("expected fail_open=false, got %v", got["fail_open"])
	}
	statsGroup, ok := got["stats"].(map[string]any)
	if !ok {
		t.Fatalf("stats should be a group; got %T", got["stats"])
	}
	if statsGroup["EMAIL"] != float64(2) {
		t.Fatalf("expected stats.EMAIL=2, got %v", statsGroup["EMAIL"])
	}
}

// TestSlogRedactionAuditLogger_NilHandlerSafe guarantees callers that
// forget to wire an audit sink get a safe no-op, not a panic.
func TestSlogRedactionAuditLogger_NilHandlerSafe(_ *testing.T) {
	audit := NewSlogRedactionAuditLogger(nil)
	audit.LogRedaction(context.Background(), &RedactionAuditEvent{})
}
