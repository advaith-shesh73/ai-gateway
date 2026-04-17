// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// This file implements HANDOFF §7.7.3 — the partial-failure guard
// test. It proves that when one /anonymize call fails mid-fan-out:
//
//   * Under failClosed=true, the aggregate ScanTextParts call fails
//     entirely with a PIIServiceError (dispatcher translates this to
//     JSON-RPC code -32010).
//   * Under failClosed=false, the call does NOT raise; the failing
//     chunk passes through untouched while the others are redacted,
//     and metrics record the breach.
//
// Partial redaction across parts is a PII leak — the caller cannot
// tell which parts were actually scrubbed. We validate the Go port
// preserves this invariant under both policies.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPIIScan_PartialFailure_FailClosedRejectsEntireScan emulates the
// §7.7.3 shape: 10 parts, the 5th /anonymize call returns HTTP 500,
// and under failClosed=true the whole ScanTextParts aggregate errors.
func TestPIIScan_PartialFailure_FailClosedRejectsEntireScan(t *testing.T) {
	const failOnCall = 5 // 1-indexed, matches HANDOFF description.
	var callSeq atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := callSeq.Add(1)
		if n == failOnCall {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	}))
	defer srv.Close()

	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          5000,
		MaxParallelChunks: 1,
		FailClosed:        true,
		Logger:            quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	parts := make([]TextPartInput, 10)
	for i := range parts {
		parts[i] = TextPartInput{Index: i, Text: "part-" + strings.Repeat("x", 4)}
	}
	anon := func(ctx context.Context, s string) (string, error) {
		return client.Anonymize(ctx, s, "pii_scan:unit")
	}
	_, err = ScanTextParts(context.Background(), parts, anon, 4, nil)
	if err == nil {
		t.Fatalf("fail-closed partial failure must error; got nil")
	}
	// Under fail-closed the error propagated from PIIClient is the
	// sentinel PIIServiceError — confirm that so a silent errgroup
	// cancel-error is rejected.
	var piiErr *PIIServiceError
	if !errors.As(err, &piiErr) {
		t.Fatalf("expected *PIIServiceError, got %T: %v", err, err)
	}
	if piiErr.Outcome != string(piiOutcomeHTTPError) {
		t.Fatalf("expected outcome=http_error, got %q", piiErr.Outcome)
	}
}

// TestPIIScan_PartialFailure_FailOpenPassesThroughFailedChunk proves
// the fail-open path does not swallow the whole batch: redactions that
// succeeded are applied, the failing chunk keeps its original text,
// and a PII-metric counter records the breach so SRE can alert on it.
func TestPIIScan_PartialFailure_FailOpenPassesThroughFailedChunk(t *testing.T) {
	const failOnPart = "part-05"
	var mu sync.Mutex
	var seenBodies []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seenBodies = append(seenBodies, string(body))
		mu.Unlock()
		if strings.Contains(string(body), failOnPart) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	}))
	defer srv.Close()

	metrics := newCountingMetrics()
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          5000,
		MaxParallelChunks: 1,
		FailClosed:        false,
		Observer:          metrics,
		Logger:            quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	parts := make([]TextPartInput, 10)
	for i := range parts {
		parts[i] = TextPartInput{
			Index: i,
			Text:  "part-" + twoDigit(i+1),
		}
	}
	anon := func(ctx context.Context, s string) (string, error) {
		return client.Anonymize(ctx, s, "pii_scan:unit")
	}
	replacements, err := ScanTextParts(context.Background(), parts, anon, 4, nil)
	if err != nil {
		t.Fatalf("fail-open must not raise: %v", err)
	}
	// Every redacted part produced "<REDACTED>" — expect 9 replacements.
	// The failed part ("part-05") retains its original text (so no
	// replacement is emitted for it).
	if got, want := len(replacements), 9; got != want {
		t.Fatalf("expected %d replacements, got %d: %v", want, got, replacements)
	}
	if _, failedReplaced := replacements[4]; failedReplaced {
		t.Fatalf("failed-chunk part should not have a replacement: %v", replacements)
	}
	// Metric assertion: the http_error counter MUST have recorded
	// the breach. This is how SRE alerts on elevated partial-failure
	// rates. An empty metric indicates the port silently swallowed
	// the error without observability.
	if n := metrics.callCount(string(piiOutcomeHTTPError)); n != 1 {
		t.Fatalf("expected 1 http_error metric event, got %d", n)
	}
}

// twoDigit pads a non-negative integer to 2 digits.
func twoDigit(n int) string {
	if n < 10 {
		return "0" + string(rune('0'+n))
	}
	// Only runs within range [10, 99] in our tests; larger inputs
	// would need a proper formatter and are out of scope.
	return string(rune('0'+n/10)) + string(rune('0'+n%10))
}
