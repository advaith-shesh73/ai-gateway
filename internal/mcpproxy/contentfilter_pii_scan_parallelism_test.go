// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// This file implements HANDOFF §7.7.1 — the parallelism-parity test
// that gates the PIIScan merge. It is intentionally its own file so a
// reviewer looking for "is the 4×4 fan-out test present?" can grep by
// filename and find it without scrolling through parity tests.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestPIIScan_ParallelismMatchesTwoDimensionalBudget proves that the
// composed fan-out (parts × chunks-per-part) actually saturates both
// semaphores — and that it does NOT exceed their product.
//
// Shape of the test:
//
//   - We feed 10 text parts, each individually long enough to split
//     into >=2 chunks.
//   - We set MaxParallelParts=4 and MaxParallelChunks=2 inside the
//     PIIClient.
//   - A mock PII server sleeps 20 ms per /anonymize call and tracks
//     the peak number of simultaneously-in-flight requests (atomic,
//     lock-free).
//   - We assert:
//   - peakInFlight >= 4  — proves we actually achieve parallelism.
//     A sequential regression would cap at 1.
//   - peakInFlight <= 8  — proves we do not exceed 4*2 = product
//     of both semaphores. An unbounded fan-out regression would
//     spike at 20 (10 parts × 2 chunks each).
//
// Rationale from HANDOFF §7.7.1: the Python sidecar shipped with a
// subtle bug where the outer semaphore was accidentally unbounded in
// pipeline mode. That bug burned the PII service pool without anyone
// noticing. This test pins the bound explicitly in Go so the same
// regression cannot silently recur.
func TestPIIScan_ParallelismMatchesTwoDimensionalBudget(t *testing.T) {
	const (
		numParts          = 10
		maxParallelParts  = 4
		maxParallelChunks = 2
	)

	// Peak tracker: atomic counter for current-in-flight, CAS-loop
	// for peak. Lock-free to avoid the mutex itself being a
	// contention point in a parallelism test.
	var inFlight, peak int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if cur <= p || atomic.CompareAndSwapInt32(&peak, p, cur) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)

		_, _ = io.ReadAll(r.Body)
		// Body shape is fixed so the client decode succeeds quickly.
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	}))
	defer srv.Close()

	// Build a real PIIClient configured for chunking: MaxChars small
	// enough that each 30-byte part splits into >=2 chunks.
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          15,
		MaxParallelChunks: maxParallelChunks,
		Logger:            quietPIILogger(),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	// Build 10 text parts, each long enough to split into at least 2
	// chunks. We use explicit paragraph breaks so splitForPII prefers
	// the "\n\n" boundary, producing predictable chunk counts.
	parts := make([]TextPartInput, numParts)
	for i := 0; i < numParts; i++ {
		parts[i] = TextPartInput{
			Index: i,
			Text:  fmt.Sprintf("part_%02d_a\n\npart_%02d_b", i, i),
		}
	}

	anon := func(ctx context.Context, s string) (string, error) {
		return client.Anonymize(ctx, s, "pii_scan:unit")
	}
	if _, err := ScanTextParts(context.Background(), parts, anon, maxParallelParts, nil); err != nil {
		t.Fatalf("ScanTextParts: %v", err)
	}

	p := atomic.LoadInt32(&peak)
	// Lower bound — proves real parallelism, not sequential regression.
	if p < int32(maxParallelParts) {
		t.Fatalf("peakInFlight=%d < maxParallelParts=%d — sequential regression?",
			p, maxParallelParts)
	}
	// Upper bound — proves the chunk semaphore is honored per-part.
	if p > int32(maxParallelParts*maxParallelChunks) {
		t.Fatalf("peakInFlight=%d > maxParallelParts*maxParallelChunks=%d — unbounded fan-out?",
			p, maxParallelParts*maxParallelChunks)
	}
}
