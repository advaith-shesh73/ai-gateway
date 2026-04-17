// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package logsafe

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// captureLogger returns a JSON slog logger writing to a buffer so the tests
// can inspect the exact bytes that would be emitted in production.
func captureLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	return slog.New(h), &buf
}

func TestRedact_NeverEmitsRawString(t *testing.T) {
	logger, buf := captureLogger(t)
	secret := "alice@example.com called +14155550123 from 192.168.1.1"

	logger.Info("pii event", slog.Any("text", Redact(secret)))

	got := buf.String()
	require.NotContains(t, got, "alice@example.com")
	require.NotContains(t, got, "14155550123")
	require.NotContains(t, got, "192.168.1.1")
	require.Contains(t, got, "redacted=len:")
	require.Contains(t, got, "B")
}

func TestRedact_NeverEmitsRawBytes(t *testing.T) {
	logger, buf := captureLogger(t)
	secret := []byte("token=hunter2 ssn=123-45-6789")

	logger.Info("pii event", slog.Any("body", Redact(secret)))

	got := buf.String()
	require.NotContains(t, got, "hunter2")
	require.NotContains(t, got, "123-45-6789")
	require.Contains(t, got, "redacted=len:")
}

func TestRedact_NeverEmitsMapContents(t *testing.T) {
	logger, buf := captureLogger(t)
	mapping := map[string]string{
		"alice@example.com": "<EMAIL_0>",
		"Bob Smith":         "<PERSON_0>",
		"+14155550123":      "<PHONE_0>",
	}

	logger.Info("pii event", slog.Any("mapping", Redact(mapping)))

	got := buf.String()
	require.NotContains(t, got, "alice@example.com")
	require.NotContains(t, got, "Bob Smith")
	require.NotContains(t, got, "+14155550123")
	require.NotContains(t, got, "EMAIL_0")
	require.NotContains(t, got, "PERSON_0")
	require.NotContains(t, got, "PHONE_0")
	require.Contains(t, got, "redacted=entries:3")
}

func TestRedact_NeverEmitsStatsContents(t *testing.T) {
	logger, buf := captureLogger(t)
	stats := map[string]int{
		"EMAIL":  2,
		"PERSON": 7,
		"PHONE":  1,
	}

	logger.Info("pii event", slog.Any("stats", Redact(stats)))

	got := buf.String()
	// Both keys and counts are considered tainted when combined.
	require.NotContains(t, got, "EMAIL")
	require.NotContains(t, got, "PERSON")
	require.NotContains(t, got, "PHONE")
	require.Contains(t, got, "redacted=entries:3")
}

func TestRedact_SliceOfStrings(t *testing.T) {
	logger, buf := captureLogger(t)
	chunks := []string{
		"alice@example.com said hello",
		"bob lives at 1.2.3.4",
	}

	logger.Info("chunks", slog.Any("parts", Redact(chunks)))

	got := buf.String()
	require.NotContains(t, got, "alice@example.com")
	require.NotContains(t, got, "1.2.3.4")
	require.Contains(t, got, "redacted=items:2")
}

func TestRedact_NilValue(t *testing.T) {
	logger, buf := captureLogger(t)

	logger.Info("nil event", slog.Any("text", Redact(nil)))

	require.Contains(t, buf.String(), "redacted=<nil>")
}

func TestRedact_MapStringAny(t *testing.T) {
	logger, buf := captureLogger(t)
	payload := map[string]any{
		"mapping": map[string]string{"alice": "X"},
		"stats":   map[string]int{"EMAIL": 1},
	}

	logger.Info("pii response", slog.Any("body", Redact(payload)))

	got := buf.String()
	require.NotContains(t, got, "alice")
	require.NotContains(t, got, "EMAIL")
	require.Contains(t, got, "redacted=entries:2")
}

func TestRedact_OpaqueValue(t *testing.T) {
	type secret struct{ email string }
	logger, buf := captureLogger(t)
	s := secret{email: "eve@example.com"}

	logger.Info("struct", slog.Any("v", Redact(s)))

	got := buf.String()
	require.NotContains(t, got, "eve@example.com")
	require.Contains(t, got, "redacted=<opaque>")
}

func TestRedact_FmtStringerFallback(t *testing.T) {
	logger, buf := captureLogger(t)
	s := tattleStringer{"super-secret"}

	logger.Info("stringy", slog.Any("v", Redact(s)))

	got := buf.String()
	require.NotContains(t, got, "super-secret")
	require.Contains(t, got, "redacted=<stringer>")
}

func TestRedact_StringMethodAlsoSafe(t *testing.T) {
	// Ensures that a careless log site that calls fmt.Sprintf("%s", Redact(x))
	// still cannot print the raw value.
	r := Redact("topsecret")
	rs, ok := r.(interface{ String() string })
	require.True(t, ok, "Redact return value must be a Stringer")
	require.NotContains(t, rs.String(), "topsecret")
	require.Contains(t, rs.String(), "redacted=len:")
}

func TestRedact_UsableWithAttrsAndGroup(t *testing.T) {
	// Exercises LogValuer through a grouped handler to catch handler
	// implementations that bypass LogValue.
	logger, buf := captureLogger(t)

	logger.LogAttrs(context.Background(), slog.LevelInfo, "evt",
		slog.Group("pii",
			slog.Any("mapping", Redact(map[string]string{"a": "b"})),
			slog.Any("text", Redact("bob@example.com")),
		),
	)

	got := buf.String()
	require.NotContains(t, got, "bob@example.com")
	// The key itself appears once grouped; ensure we don't see the raw value.
	require.True(t, strings.Contains(got, "redacted=len:") && strings.Contains(got, "redacted=entries:1"))
}

// tattleStringer is a fmt.Stringer whose raw form would leak secrets. The
// Redact path must never call String() and leak this value.
type tattleStringer struct{ s string }

func (t tattleStringer) String() string { return t.s }
