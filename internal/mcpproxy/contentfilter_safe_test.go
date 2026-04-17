// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSafeGo_RecoversPanicsAsErrors verifies the unit-of-work helper
// converts a panic into a structured error with a stack trace rather
// than letting the process die. This is the guardrail that makes the
// fan-out workers in anonymize / scan / hedge safe to embed inside an
// errgroup.
func TestSafeGo_RecoversPanicsAsErrors(t *testing.T) {
	err := safeGo("unit test worker", func() error {
		panic("boom")
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "unit test worker panic")
	require.Contains(t, err.Error(), "boom")
	// Stack traces make the error actionable; failing without one
	// would defeat the purpose of catching the panic at all.
	require.Contains(t, err.Error(), "mcpproxy")
}

// TestSafeGo_PropagatesRegularErrors confirms the wrapper is a no-op
// for the non-panic path — the caller's errgroup semantics must be
// preserved exactly.
func TestSafeGo_PropagatesRegularErrors(t *testing.T) {
	want := errors.New("sentinel")
	got := safeGo("unit test worker", func() error { return want })
	require.ErrorIs(t, got, want)
}

// TestScanTextParts_PanicInsideAnonymizeIsNotFatal proves the contract
// at the fan-out call site: a panic inside the injected AnonymizeFn
// becomes a returned error, never a process crash. Without safeGo the
// test would take down the whole go-test runner.
func TestScanTextParts_PanicInsideAnonymizeIsNotFatal(t *testing.T) {
	boom := func(_ context.Context, text string) (string, error) {
		if strings.Contains(text, "trigger") {
			panic("anonymize exploded on " + text)
		}
		return text, nil
	}
	parts := []TextPartInput{
		{Index: 0, Text: "safe"},
		{Index: 1, Text: "trigger"},
		{Index: 2, Text: "also safe"},
	}
	_, err := ScanTextParts(context.Background(), parts, boom, 2, nil)
	require.Error(t, err, "panic must be caught and surfaced")
	require.Contains(t, err.Error(), "pii part worker panic")
	require.Contains(t, err.Error(), "anonymize exploded")
}

// panickingRoundTripper explodes inside the transport — a realistic
// proxy for "the HTTP client library hit an unexpected nil" class of
// bug. Before safeGo this would take the process down.
type panickingRoundTripper struct{}

func (p *panickingRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	panic("transport exploded mid-request")
}

// TestPIIClient_PanicInsideTransportIsNotFatal proves the same contract
// holds one level down, inside the chunk worker. We inject a transport
// that panics partway through the request; without safeGo this would
// surface as a runtime crash under the errgroup.
func TestPIIClient_PanicInsideTransportIsNotFatal(t *testing.T) {
	c, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Transport: &panickingRoundTripper{}, Timeout: 2 * time.Second},
		URL:               "http://unit-test.invalid/anonymize",
		Timeout:           2 * time.Second,
		MaxChars:          100,
		MaxParallelChunks: 2,
		FailClosed:        true, // surface the error path deterministically
		Logger:            quietPIILogger(),
	})
	require.NoError(t, err)

	// Text is long enough that it will be split into multiple chunks,
	// so we exercise the fan-out goroutine.
	text := strings.Repeat("a\n\n", 200)
	_, err = c.Anonymize(context.Background(), text, "test")
	require.Error(t, err)
	// Either the chunk-worker panic surfaces directly, or the breaker/
	// client wraps it as a PII service error. Either way, the process
	// must still be alive to run this assertion — that is the point.
	msg := err.Error()
	require.True(t,
		strings.Contains(msg, "pii chunk worker panic") ||
			strings.Contains(msg, "pii service") ||
			strings.Contains(msg, "transport exploded"),
		"expected structured error, got %q", msg,
	)
}
