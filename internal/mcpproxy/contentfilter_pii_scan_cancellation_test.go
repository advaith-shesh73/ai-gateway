// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// This file implements HANDOFF §7.7.5 — the cancellation-propagation
// guard test. It proves:
//
//   * When the caller cancels a ScanTextParts, every in-flight PII
//     request is aborted (context propagation across goroutines).
//   * No /anonymize call is allowed to "complete" (reach the response
//     write) after the caller cancels; the stub server records the
//     count of completed writes and we assert it is zero within a
//     200 ms grace window.
//   * The circuit breaker does NOT transition to OPEN — context.Canceled
//     is neutral per HANDOFF §4.11 so we can distinguish caller-side
//     cancellation (browser tab closed) from downstream failure.

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// TestPIIScan_CancellationPropagatesAndBreakerStaysClosed mirrors the
// §7.7.5 shape: stub PII server blocks 500 ms per request; caller
// cancels after 50 ms; asserts zero completed responses and breaker
// state does not leave CLOSED.
func TestPIIScan_CancellationPropagatesAndBreakerStaysClosed(t *testing.T) {
	const (
		serverDelay = 500 * time.Millisecond
		cancelDelay = 50 * time.Millisecond
		graceWindow = 200 * time.Millisecond
		numParts    = 6
	)

	var completedWrites int32 // incremented only if the handler manages to finish.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Respect the request context; caller cancellation must
		// abort this select. This is what a well-behaved downstream
		// does; we use it to assert that a cancelled PIIScan cannot
		// smuggle a response back.
		select {
		case <-time.After(serverDelay):
		case <-r.Context().Done():
			return
		}
		_, _ = io.ReadAll(r.Body)
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
		atomic.AddInt32(&completedWrites, 1)
	}))
	defer srv.Close()

	// Build breaker with a FakeClock so the test doesn't depend on
	// wall-time elapsed between cancel and assertions.
	breaker := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 2, ResetTimeout: 30 * time.Second},
		func() time.Time { return time.Unix(0, 0) },
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		nil,
	)
	client, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
		URL:               srv.URL,
		Timeout:           5 * time.Second,
		MaxChars:          5000,
		MaxParallelChunks: 2,
		Breaker:           breaker,
		FailClosed:        true,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}

	parts := make([]TextPartInput, numParts)
	for i := range parts {
		parts[i] = TextPartInput{Index: i, Text: "text-" + twoDigit(i)}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		anon := func(ctx context.Context, s string) (string, error) {
			return client.Anonymize(ctx, s, "pii_scan:cancel")
		}
		_, _ = ScanTextParts(ctx, parts, anon, 4, nil)
		close(done)
	}()

	time.Sleep(cancelDelay)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("ScanTextParts hung after cancel")
	}

	// Wait the grace window for any straggling writes that managed
	// to start responding before cancel landed. After the grace
	// window, completedWrites MUST still be zero.
	time.Sleep(graceWindow)
	if n := atomic.LoadInt32(&completedWrites); n != 0 {
		t.Fatalf("expected 0 completed PII responses after cancel; got %d", n)
	}

	// Critically: the breaker must NOT be OPEN. context.Canceled is
	// neutral per §4.11 — tripping the breaker here would mean
	// browser-tab-closed events cause the pipeline to reject every
	// subsequent request for 30s.
	if st := breaker.State(); st != CircuitClosed {
		t.Fatalf("breaker should stay CLOSED under caller cancellation; got %v", st)
	}
}
