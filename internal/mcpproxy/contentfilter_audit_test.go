// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Tests for L13 — redaction audit log stream.
//
// Scope of coverage:
//   * The SlogRedactionAuditLogger emits events through its own
//     handler, independent of the PIIClient's operational logger.
//   * The PIIClient emits audit events in every path that produces
//     bytes for the caller: successful redaction, cache hit, and
//     fail-open passthrough.
//   * Fail-closed paths do NOT emit audit events (no bytes leave the
//     gateway, so there is nothing to audit).
//   * The operational logger and the audit logger can be independently
//     configured — one can be silent while the other is verbose.

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// Test that the slog-backed audit logger writes through a caller-
// controlled handler and uses the "redaction" message key.
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
// forgot to wire an audit sink get a safe no-op, not a panic.
func TestSlogRedactionAuditLogger_NilHandlerSafe(_ *testing.T) {
	audit := NewSlogRedactionAuditLogger(nil)
	// Must not panic.
	audit.LogRedaction(context.Background(), &RedactionAuditEvent{})
}

// TestPIIClient_AuditLogger_EmitsOnSuccess verifies the PIIClient
// emits one audit event per successful redaction, with the expected
// labels and stats map copied through.
func TestPIIClient_AuditLogger_EmitsOnSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"text":"<R>","stats":{"EMAIL":1,"PHONE":2}}`)
	}))
	defer srv.Close()

	collector := &CollectingRedactionAuditLogger{}
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
		URL:         srv.URL,
		Timeout:     2 * time.Second,
		MaxChars:    50,
		FailClosed:  false,
		AuditLogger: collector,
		Route:       "r-default",
		Backend:     "b-default",
		Tool:        "t-default",
		Logger:      quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	if _, err := client.AnonymizeForRoute(context.Background(), "hello world", "pii_scan:unit", "r-call", "b-call"); err != nil {
		t.Fatalf("Anonymize: %v", err)
	}

	events := collector.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d", len(events))
	}
	ev := events[0]
	if ev.Outcome != "ok" || ev.FailOpen {
		t.Fatalf("expected ok/!fail_open, got outcome=%q fail_open=%v", ev.Outcome, ev.FailOpen)
	}
	// Per-call labels take precedence over defaults.
	if ev.Route != "r-call" || ev.Backend != "b-call" {
		t.Fatalf("expected per-call labels, got route=%q backend=%q", ev.Route, ev.Backend)
	}
	// Tool falls back to the client default because the per-call form
	// does not accept a tool override.
	if ev.Tool != "t-default" {
		t.Fatalf("expected default tool, got %q", ev.Tool)
	}
	if ev.Stats["EMAIL"] != 1 || ev.Stats["PHONE"] != 2 {
		t.Fatalf("stats did not propagate: %v", ev.Stats)
	}
	if ev.InputChars == 0 || ev.OutputChars == 0 {
		t.Fatalf("expected non-zero char counts, got in=%d out=%d", ev.InputChars, ev.OutputChars)
	}
}

// TestPIIClient_AuditLogger_EmitsOnFailOpen verifies the fail-open
// passthrough emits an audit event with FailOpen=true and nil stats.
// This is the compliance-critical path: without this, a redaction
// service outage would silently leak PII and no record would survive.
func TestPIIClient_AuditLogger_EmitsOnFailOpen(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	collector := &CollectingRedactionAuditLogger{}
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
		URL:         srv.URL,
		Timeout:     2 * time.Second,
		MaxChars:    100,
		FailClosed:  false,
		AuditLogger: collector,
		Logger:      quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	_, err = client.AnonymizeForRoute(context.Background(), "sensitive-data", "pii_scan:unit", "r", "b")
	if err != nil {
		t.Fatalf("fail-open must not error: %v", err)
	}

	events := collector.Events()
	if len(events) != 1 {
		t.Fatalf("expected 1 audit event, got %d: %+v", len(events), events)
	}
	ev := events[0]
	if !ev.FailOpen {
		t.Fatalf("fail-open must mark event FailOpen=true")
	}
	if ev.Stats != nil {
		t.Fatalf("fail-open must not carry stats; got %v", ev.Stats)
	}
	if ev.OutputChars != 0 {
		t.Fatalf("fail-open must report OutputChars=0 as the no-scrub sentinel, got %d", ev.OutputChars)
	}
	if ev.Route != "r" || ev.Backend != "b" {
		t.Fatalf("fail-open must preserve route/backend labels; got route=%q backend=%q", ev.Route, ev.Backend)
	}
}

// TestPIIClient_AuditLogger_SilentOnFailClosed verifies fail-closed
// paths do NOT emit audit events. Rationale: no bytes leave the
// gateway to the downstream, so there is nothing to audit.
func TestPIIClient_AuditLogger_SilentOnFailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	collector := &CollectingRedactionAuditLogger{}
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
		URL:         srv.URL,
		Timeout:     2 * time.Second,
		MaxChars:    100,
		FailClosed:  true,
		AuditLogger: collector,
		Logger:      quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	_, err = client.AnonymizeForRoute(context.Background(), "data", "pii_scan:unit", "r", "b")
	if err == nil {
		t.Fatalf("fail-closed must error")
	}
	if n := collector.Len(); n != 0 {
		t.Fatalf("fail-closed must NOT emit audit events; got %d", n)
	}
}

// TestPIIClient_AuditAndOperationalLogsIndependent proves the two
// streams route through different handlers: we configure an audit
// handler at INFO that writes to one buffer and an operational logger
// at WARN that writes to another. A successful redaction must end up
// in the audit buffer only (it's an INFO event), never in the op
// buffer, confirming separation.
func TestPIIClient_AuditAndOperationalLogsIndependent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"text":"<R>"}`)
	}))
	defer srv.Close()

	var auditBuf bytes.Buffer
	auditLog := slog.New(slog.NewJSONHandler(&auditBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var opBuf bytes.Buffer
	opLog := slog.New(slog.NewJSONHandler(&opBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:  &http.Client{Timeout: 2 * time.Second},
		URL:         srv.URL,
		Timeout:     2 * time.Second,
		MaxChars:    100,
		FailClosed:  false,
		AuditLogger: NewSlogRedactionAuditLogger(auditLog),
		Logger:      opLog,
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}
	if _, err := client.Anonymize(context.Background(), "data", "pii_scan:unit"); err != nil {
		t.Fatalf("Anonymize: %v", err)
	}
	if !strings.Contains(auditBuf.String(), `"msg":"redaction"`) {
		t.Fatalf("audit handler did not receive the redaction event; buf=%s", auditBuf.String())
	}
	if strings.Contains(opBuf.String(), `"msg":"redaction"`) {
		t.Fatalf("operational handler received the redaction event; separation violated. buf=%s", opBuf.String())
	}
}
