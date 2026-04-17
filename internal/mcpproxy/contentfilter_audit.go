// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"
)

// RedactionAuditEvent is one record that flows through the audit
// stream. The shape is intentionally narrow:
//
//   - no raw text (the whole point of an audit log is to tell you
//     *what class* of data was redacted, not replay the data itself);
//   - no free-form message (audit consumers parse JSON keys, not
//     English sentences);
//   - every label needed to tie the event back to the triggering
//     request (route + backend + tool + pii_context).
//
// Stats carries counts per redaction category as reported by the PII
// service (e.g. {"EMAIL": 2, "PHONE": 1}). A successful call with an
// empty stats map still emits an event so operators can alert on
// absence — "no redaction event for this route in the last 24 hours"
// is a legitimate compliance question.
type RedactionAuditEvent struct {
	// Timestamp is the wall-clock time the PII service returned. The
	// audit sink may overwrite or ignore this (most JSON ingesters
	// stamp on arrival), but providing it here lets offline replays
	// reconstruct ordering without relying on log-arrival jitter.
	Timestamp time.Time
	// Route is the FilterRequest route label (may be empty when the
	// call originated from a code path without route tagging, e.g.
	// background refresh jobs). Prefer to always set this.
	Route string
	// Backend is the downstream backend label (may be empty).
	Backend string
	// Tool is the MCP tool name that triggered the call (may be empty
	// for non-tool scans, e.g. arguments scrubbing).
	Tool string
	// PIIContext is the metric/cache label passed to the PII client
	// (e.g. "pii_scan:supportgpt.response"). Non-empty; "-" if unset.
	PIIContext string
	// InputChars is the number of characters the client submitted.
	// Useful for cost/latency correlations without leaking content.
	InputChars int
	// OutputChars is the number of characters the PII service
	// returned. Zero indicates a fail-open fallback.
	OutputChars int
	// Stats is the per-category redaction count map. nil when the
	// service did not emit one (e.g. fail-open fallbacks). Callers
	// should treat nil and empty as equivalent.
	Stats map[string]int
	// Elapsed is the backend round-trip time. Useful for correlating
	// slow redactions with specific tool or route combinations.
	Elapsed time.Duration
	// Outcome is one of the piiOutcome strings ("ok", "cache_hit",
	// "fail_open", ...). Audit consumers filter on this.
	Outcome string
	// FailOpen is true iff the outbound text was NOT actually
	// redacted (the client fell through to return the original). This
	// is the most important bit for compliance teams — it tells them
	// which events correspond to an actual scrub and which are just
	// passthroughs that may contain PII.
	FailOpen bool
}

// RedactionAuditLogger is the narrow interface the PII client calls
// when it wants to emit an audit event. Keeping the interface narrow
// lets tests substitute a simple in-memory collector and lets
// production use a [SlogRedactionAuditLogger] routed to a dedicated
// sink (separate file, SIEM collector, Kafka topic, etc.).
type RedactionAuditLogger interface {
	// LogRedaction emits one audit event. Implementations must be
	// safe for concurrent use and should NOT block the caller — they
	// should hand off to an async sink or a buffered writer. The ctx
	// is passed so implementations can extract trace IDs if they
	// want them in the record; callers should not rely on the ctx
	// being respected for cancellation.
	//
	// ev is passed by pointer for efficiency (the event struct is
	// ~144 bytes). Implementations must NOT retain ev beyond the
	// call — if they need to outlive the call they must copy
	// relevant fields. Callers likewise must not mutate ev after
	// the call returns.
	LogRedaction(ctx context.Context, ev *RedactionAuditEvent)
}

// NoopRedactionAuditLogger is the default when an application has
// not wired an audit sink yet. It discards everything. This lets the
// rest of the pipeline call LogRedaction unconditionally without a
// nil-check.
type NoopRedactionAuditLogger struct{}

// LogRedaction drops the event on the floor.
func (NoopRedactionAuditLogger) LogRedaction(context.Context, *RedactionAuditEvent) {}

// SlogRedactionAuditLogger is the production default: it wraps a
// [slog.Logger] whose handler is usually configured to write to a
// dedicated file/sink. Separating the handler from the regular
// operational logger is the whole point of the stream — audit records
// have different retention, different access control, and different
// schemas from operational logs.
//
// Note: we deliberately do NOT reuse the PIIClient's logger field
// because operators legitimately want audit records to persist on
// disk even when operational logs are rate-limited or discarded
// (e.g. DEBUG off in production).
type SlogRedactionAuditLogger struct {
	logger *slog.Logger
}

// NewSlogRedactionAuditLogger wraps a pre-built [slog.Logger]. The
// caller owns the lifecycle of the underlying handler (opening the
// audit file, rotating it, etc.); this type does no I/O of its own.
// If logger is nil, a discard logger is used so callers can still
// safely invoke LogRedaction.
func NewSlogRedactionAuditLogger(logger *slog.Logger) *SlogRedactionAuditLogger {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &SlogRedactionAuditLogger{logger: logger}
}

// LogRedaction emits the event via slog at INFO level. The record uses
// a stable set of keys so downstream parsers can match exact strings
// instead of regexing English prose. The "stats" group carries the
// per-category counts; keys inside the group match the PII service's
// output verbatim so SIEM dashboards can group on them directly.
//
// The level is INFO (never WARN) because a redaction is a normal
// business event — escalating it to WARN would swamp alerting systems
// that are meant to catch anomalies, not every successful scrub.
func (l *SlogRedactionAuditLogger) LogRedaction(ctx context.Context, ev *RedactionAuditEvent) {
	if ev == nil {
		return
	}
	// Always attach the primary fan-out labels first so their position
	// is stable in the output. Audit consumers frequently bolt ad-hoc
	// regexes onto the first few fields of each line; shifting the
	// field order would break them silently.
	attrs := []slog.Attr{
		slog.Time("timestamp", ev.Timestamp),
		slog.String("outcome", ev.Outcome),
		slog.Bool("fail_open", ev.FailOpen),
		slog.String("route", ev.Route),
		slog.String("backend", ev.Backend),
		slog.String("tool", ev.Tool),
		slog.String("pii_context", ev.PIIContext),
		slog.Int("input_chars", ev.InputChars),
		slog.Int("output_chars", ev.OutputChars),
		slog.Duration("elapsed", ev.Elapsed),
	}
	if len(ev.Stats) > 0 {
		// slog.Group is the stable way to nest per-category counts
		// under a single JSON key ("stats": {"EMAIL": 2, ...}) when
		// the handler is a JSON handler. For text handlers this
		// becomes "stats.EMAIL=2 ..." which is equally greppable.
		statsAttrs := make([]any, 0, len(ev.Stats))
		for k, v := range ev.Stats {
			statsAttrs = append(statsAttrs, slog.Int(k, v))
		}
		attrs = append(attrs, slog.Group("stats", statsAttrs...))
	}
	l.logger.LogAttrs(ctx, slog.LevelInfo, "redaction", attrs...)
}

// CollectingRedactionAuditLogger buffers every event in memory and
// exposes them for assertion. It is safe for concurrent use and is
// the default handler in unit tests.
//
// Applications MUST NOT use this type in production — it has no
// eviction policy and will grow without bound.
type CollectingRedactionAuditLogger struct {
	mu     sync.Mutex
	events []RedactionAuditEvent
}

// LogRedaction appends ev to the internal slice under a lock. A copy
// is stored so the caller can safely reuse its pointer.
func (c *CollectingRedactionAuditLogger) LogRedaction(_ context.Context, ev *RedactionAuditEvent) {
	if ev == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, *ev)
}

// Events returns a defensive copy of the accumulated events. The copy
// keeps the caller safe from the collector mutating the backing array
// after the snapshot.
func (c *CollectingRedactionAuditLogger) Events() []RedactionAuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]RedactionAuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

// Len returns the number of buffered events without copying.
func (c *CollectingRedactionAuditLogger) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}
