// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package logsafe provides helpers that prevent tainted values (original
// text, PII mapping objects, raw stats payloads, opaque HTTP bodies, etc.)
// from reaching structured loggers verbatim.
//
// Rationale (HANDOFF_GO_PORT_REFERENCE §4.7, Jeff Dean P1 #13):
// The Python sidecar leaked PII into its own log stream whenever it logged
// the raw response payload from the PII service. Every attribute that could
// carry tainted bytes in the Go port MUST be wrapped with [Redact] so only
// a safe shape — byte length or element count — is ever emitted.
package logsafe

import (
	"fmt"
	"log/slog"
	"strconv"
)

// Redact wraps an arbitrary value so that [slog.Logger] emits only its shape
// — the number of bytes for strings / byte slices or the element count for
// map and slice values — never the value itself.
//
// Use Redact for every attribute whose value could plausibly contain PII or
// another raw server payload. In particular wrap:
//
//   - `text`        (MCP text part content, pre- or post-anonymization)
//   - `mapping`     (entity → placeholder map returned by the PII service)
//   - `stats`       (entity-type counts, may include labels with PII)
//   - `body`        (raw HTTP response bodies from PII or Jira)
//
// Example (the only form log sites should use):
//
//	logger.Info("pii call ok",
//	    slog.Any("body", logsafe.Redact(respBody)),
//	    slog.Any("mapping", logsafe.Redact(mapping)),
//	)
//
// The wrapper is safe for `nil` and zero values; it records `nil` verbatim
// and every other value as its len-only shape.
func Redact(v any) slog.LogValuer {
	return redactor{v: v}
}

// redactor implements [slog.LogValuer] so slog emits Redact.LogValue()
// instead of marshalling the underlying value.
type redactor struct {
	v any
}

// LogValue returns the shape of the wrapped value. It never returns the
// value itself — that is the entire contract of this package.
func (r redactor) LogValue() slog.Value {
	if r.v == nil {
		return slog.StringValue("redacted=<nil>")
	}
	switch x := r.v.(type) {
	case string:
		return slog.StringValue("redacted=len:" + strconv.Itoa(len(x)) + "B")
	case []byte:
		return slog.StringValue("redacted=len:" + strconv.Itoa(len(x)) + "B")
	case []string:
		return slog.StringValue("redacted=items:" + strconv.Itoa(len(x)))
	case map[string]string:
		return slog.StringValue("redacted=entries:" + strconv.Itoa(len(x)))
	case map[string]any:
		return slog.StringValue("redacted=entries:" + strconv.Itoa(len(x)))
	case map[string]int:
		return slog.StringValue("redacted=entries:" + strconv.Itoa(len(x)))
	case map[string]int64:
		return slog.StringValue("redacted=entries:" + strconv.Itoa(len(x)))
	case fmt.Stringer:
		_ = x
		return slog.StringValue("redacted=<stringer>")
	default:
		return slog.StringValue("redacted=<opaque>")
	}
}

// String satisfies [fmt.Stringer] so that any fallthrough path which calls
// `fmt.Sprintf("%s", logsafe.Redact(x))` cannot accidentally print the raw
// value either.
func (r redactor) String() string {
	return r.LogValue().String()
}
