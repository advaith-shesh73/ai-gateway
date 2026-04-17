// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// This file covers L10 — "all-or-nothing under fail-open" for the
// PII chunk fan-out inside a single Anonymize call.
//
// The bug class this protects against: without rollback, a long input
// that splits into N chunks can come back as a *mix* of redacted and
// raw chunks when the PII service flakes mid-batch. Downstream
// consumers see a "successfully filtered" payload that in fact still
// contains unredacted PII in one section. Here we prove that when ANY
// chunk falls open, the whole output reverts to the caller's original
// text and a dedicated metric (`partial_rollback`) fires so SRE can
// alert on the class.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TestPIIChunk_FailOpen_RollsAllChunksBackToOriginal drives the chunk
// fan-out path directly: input length > MaxChars forces the split, one
// of the backend calls fails, and under fail-open the WHOLE output
// must equal the original input — not a mix of redacted segments plus
// one raw segment.
func TestPIIChunk_FailOpen_RollsAllChunksBackToOriginal(t *testing.T) {
	const failOnCall = 2 // 1-indexed; second chunk call trips 500
	var callSeq atomic.Int32
	var seenBodies atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenBodies.Add(1)
		n := callSeq.Add(1)
		if n == failOnCall {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.ReadAll(r.Body)
		// Success returns a marker value that is obviously distinct
		// from the caller's input, so any leak stands out in diffs.
		_, _ = io.WriteString(w, `{"text":"<REDACTED-OK>"}`)
	}))
	defer srv.Close()

	metrics := newCountingMetrics()
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          10,
		MaxParallelChunks: 4,
		FailClosed:        false,
		Observer:          metrics,
		Logger:            quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	// 3 chunks of length 10 each = forces chunking with one guaranteed
	// failing chunk in the middle.
	original := strings.Repeat("A", 10) + strings.Repeat("B", 10) + strings.Repeat("C", 10)

	got, err := client.Anonymize(context.Background(), original, "pii_scan:unit")
	if err != nil {
		t.Fatalf("fail-open must not raise even on partial failure: %v", err)
	}

	// Strict all-or-nothing: any leak would show up as a string that
	// contains the "<REDACTED-OK>" marker. Rollback must produce the
	// literal original input.
	if got != original {
		t.Fatalf("all-or-nothing violated. Expected exact original, got %q", got)
	}
	if strings.Contains(got, "REDACTED") {
		t.Fatalf("rolled-back output leaked a redaction marker: %q", got)
	}

	// Metric must record the rollback so SRE can alert. A missing
	// counter here means a silent leak-class regression.
	if n := metrics.callCount(string(piiOutcomePartialRollback)); n != 1 {
		t.Fatalf("expected 1 partial_rollback metric, got %d", n)
	}
	// Sanity: at least one of the three chunk calls reached the fake
	// backend. Without that, the test would trivially pass because no
	// concurrency actually happened.
	if seenBodies.Load() < 2 {
		t.Fatalf("expected backend to see at least 2 chunk requests, got %d", seenBodies.Load())
	}
}

// TestPIIChunk_AllSucceed_NoRollbackMetric is the control case: when
// every chunk succeeds, the joined redaction is preserved and the
// rollback metric must NOT fire. Without this, a bug that *always*
// rolls back would still pass the happy path and we'd never notice.
func TestPIIChunk_AllSucceed_NoRollbackMetric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"text":"<X>"}`)
	}))
	defer srv.Close()

	metrics := newCountingMetrics()
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          10,
		MaxParallelChunks: 4,
		FailClosed:        false,
		Observer:          metrics,
		Logger:            quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	original := strings.Repeat("A", 10) + strings.Repeat("B", 10) + strings.Repeat("C", 10)
	got, err := client.Anonymize(context.Background(), original, "pii_scan:unit")
	if err != nil {
		t.Fatalf("happy path errored: %v", err)
	}
	// Output must be a pure concatenation of redacted chunks — no raw
	// input leaks.
	if strings.Contains(got, "A") || strings.Contains(got, "B") || strings.Contains(got, "C") {
		t.Fatalf("happy path leaked original chunk content: %q", got)
	}
	if n := metrics.callCount(string(piiOutcomePartialRollback)); n != 0 {
		t.Fatalf("partial_rollback must NOT fire when every chunk succeeds; got %d", n)
	}
}
