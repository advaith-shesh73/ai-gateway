// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package fakepii

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// anonymize posts {"text":text} to /anonymize and returns the parsed
// response plus the HTTP status so the test can distinguish healthy
// 200s from injected failure statuses.
func anonymize(t *testing.T, s *Server, text string) (map[string]any, int) {
	t.Helper()
	body, err := json.Marshal(map[string]string{"text": text})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(context.Background(),
		http.MethodPost, s.URL+"/anonymize", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload))
	return payload, resp.StatusCode
}

func TestFakePII_HealthAlwaysOK(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	resp, err := http.Get(s.URL + "/health")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestFakePII_AnonymizesEmailAndName(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	payload, status := anonymize(t, s, "Contact Jane Doe at jane@example.com")
	require.Equal(t, http.StatusOK, status)
	text := payload["text"].(string)
	require.NotContains(t, text, "Jane Doe")
	require.NotContains(t, text, "jane@example.com")
	require.Contains(t, text, "<EMAIL_1>")
	require.Contains(t, text, "<PERSON_1>")
}

func TestFakePII_AnonymizesIPAndPhone(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	payload, status := anonymize(t, s, "Server 10.0.0.5 reachable at 555-123-4567")
	require.Equal(t, http.StatusOK, status)
	text := payload["text"].(string)
	require.NotContains(t, text, "10.0.0.5")
	require.NotContains(t, text, "555-123-4567")
	require.Contains(t, text, "<IP_1>")
	require.Contains(t, text, "<PHONE_1>")
}

func TestFakePII_EmailBeforePersonOrdering(t *testing.T) {
	// The email "Jane.Doe@x.co" would false-match the person regex
	// if person were applied first. Verify the redactor preserves
	// the Python mock's ordering (EMAIL → PERSON → IP → PHONE).
	s := New()
	t.Cleanup(s.Close)
	payload, status := anonymize(t, s, "write Jane.Doe@example.com today")
	require.Equal(t, http.StatusOK, status)
	text := payload["text"].(string)
	require.Contains(t, text, "<EMAIL_1>")
	require.NotContains(t, text, "<PERSON_1>",
		"email must be anonymized before person regex runs")
}

func TestFakePII_EmptyTextReturnsEmpty(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	payload, status := anonymize(t, s, "")
	require.Equal(t, http.StatusOK, status)
	require.Empty(t, payload["text"])
}

func TestFakePII_StatsOnlyReportsNonZeroCategories(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	payload, status := anonymize(t, s, "Jane Doe says hello")
	require.Equal(t, http.StatusOK, status)
	stats, ok := payload["stats"].(map[string]any)
	require.True(t, ok, "stats must be a map when entities present")
	require.Contains(t, stats, "PERSON")
	require.NotContains(t, stats, "EMAIL")
	require.NotContains(t, stats, "PHONE")
	require.NotContains(t, stats, "IP")
}

func TestFakePII_SetFailureReturnsInjectedStatus(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	s.SetFailure(500)
	_, status := anonymize(t, s, "anything")
	require.Equal(t, http.StatusInternalServerError, status)
	require.Equal(t, 1, s.FailureCount())
}

func TestFakePII_SetFailureZeroClears(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	s.SetFailure(503)
	_, status := anonymize(t, s, "first")
	require.Equal(t, http.StatusServiceUnavailable, status)

	s.SetFailure(0)
	_, status = anonymize(t, s, "second")
	require.Equal(t, http.StatusOK, status)
}

func TestFakePII_SetDelayObservedByCaller(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	s.SetDelay(75 * time.Millisecond)
	start := time.Now()
	_, status := anonymize(t, s, "please wait")
	elapsed := time.Since(start)
	require.Equal(t, http.StatusOK, status)
	require.GreaterOrEqual(t, elapsed, 70*time.Millisecond,
		"delay must apply to /anonymize response")
}

func TestFakePII_InFlightAndMaxInFlight(t *testing.T) {
	// Drive N concurrent /anonymize calls, each sleeping long enough
	// that all of them overlap. The peak in-flight must equal N.
	s := New()
	t.Cleanup(s.Close)
	s.SetDelay(150 * time.Millisecond)

	const n = 6
	var wg sync.WaitGroup
	var started atomic.Int32
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started.Add(1)
			_, _ = anonymize(t, s, "payload")
		}()
	}

	// Let all clients start and contend.
	require.Eventually(t, func() bool {
		return s.InFlight() == n
	}, time.Second, 5*time.Millisecond,
		"server should observe all n clients in flight")

	wg.Wait()
	require.Equal(t, n, s.MaxInFlight())
	require.Equal(t, 0, s.InFlight(), "in-flight drains to zero after all calls complete")
	require.Equal(t, n, s.CallCount())
}

func TestFakePII_ResetClearsState(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	_, _ = anonymize(t, s, "Jane Doe")
	s.SetFailure(500)
	s.SetDelay(20 * time.Millisecond)
	_, _ = anonymize(t, s, "breakage")
	require.GreaterOrEqual(t, s.CallCount(), 1)
	require.GreaterOrEqual(t, s.FailureCount(), 1)

	s.Reset()
	require.Equal(t, 0, s.CallCount())
	require.Equal(t, 0, s.FailureCount())
	require.Equal(t, 0, s.InFlight())
	require.Equal(t, 0, s.MaxInFlight())

	// Reset clears delay + failure — the next request completes fast + 200.
	start := time.Now()
	_, status := anonymize(t, s, "after reset")
	require.Equal(t, http.StatusOK, status)
	require.Less(t, time.Since(start), 15*time.Millisecond,
		"delay should have been cleared")
}

func TestFakePII_AnonymizeRespectsContextCancellation(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	s.SetDelay(500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	body, err := json.Marshal(map[string]string{"text": "anything"})
	require.NoError(t, err)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.URL+"/anonymize", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "caller-side context cancel aborts the request")
	require.True(t,
		strings.Contains(err.Error(), "context") ||
			strings.Contains(err.Error(), "canceled") ||
			strings.Contains(err.Error(), "deadline exceeded"),
		"expected a cancellation error, got: %v", err)
}

func TestFakePII_StatsEndpointReportsCounters(t *testing.T) {
	s := New()
	t.Cleanup(s.Close)
	_, _ = anonymize(t, s, "Jane Doe")
	s.SetFailure(500)
	_, _ = anonymize(t, s, "fail")

	resp, err := http.Get(s.URL + "/_stats")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var payload map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&payload))
	// JSON numbers decode to float64.
	require.EqualValues(t, 2, payload["call_count"])
	require.EqualValues(t, 1, payload["failure_count"])
	require.EqualValues(t, 0, payload["in_flight"])
}

func TestFakePII_ConcurrentCallsNoRace(t *testing.T) {
	// -race detector will flag any unsynchronised state access. Drive
	// many short calls in parallel with overlapping SetDelay/SetFailure
	// mutations to stress the handler + state mutex.
	s := New()
	t.Cleanup(s.Close)

	const workers = 16
	const iters = 100

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				if workerID%4 == 0 {
					s.SetDelay(time.Duration(j%5) * time.Microsecond)
				}
				if workerID%4 == 1 {
					// occasionally inject failure then clear
					if j%10 == 0 {
						s.SetFailure(503)
					} else {
						s.SetFailure(0)
					}
				}
				_, _ = anonymize(t, s, "Jane Doe sends hello@x.io")
			}
		}(i)
	}
	wg.Wait()
	require.Equal(t, workers*iters, s.CallCount())
}
