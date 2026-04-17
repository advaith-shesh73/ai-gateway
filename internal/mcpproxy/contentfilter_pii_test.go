// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// ---- test helpers ---------------------------------------------------------

// piiHandler is the minimum shape we need for a mock PII server: it
// sees the /anonymize request and returns either a 2xx or a synthetic
// error. Tests wire these via httptest.Server.
type piiHandler func(w http.ResponseWriter, _ *http.Request)

// newPIITestServer starts an httptest.Server whose /anonymize endpoint
// delegates to handler, and returns (url, stopFunc).
func newPIITestServer(t *testing.T, handler piiHandler) (string, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/anonymize", http.HandlerFunc(handler))
	srv := httptest.NewServer(mux)
	return srv.URL + "/anonymize", srv.Close
}

// quietLogger suppresses structured warnings that we *intend* to emit
// during tests (failures, circuit-open, etc.) so they don't litter
// output.
func quietPIILogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newPIIClientForTest builds a PIIClient against url with sane test
// defaults. Any field of cfgOverrides override the defaults.
func newPIIClientForTest(t *testing.T, url string, override func(*PIIClientConfig)) *PIIClient {
	t.Helper()
	cfg := PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 5 * time.Second},
		URL:               url,
		Timeout:           5 * time.Second,
		FailClosed:        false,
		MaxChars:          4000,
		MaxParallelChunks: 4,
		Logger:            quietPIILogger(),
	}
	if override != nil {
		override(&cfg)
	}
	c, err := NewPIIClient(&cfg)
	if err != nil {
		t.Fatalf("NewPIIClient: %v", err)
	}
	return c
}

// countingMetrics is a minimal PIIMetrics stub used to assert the
// client emitted the expected outcome labels.
type countingMetrics struct {
	mu        sync.Mutex
	calls     map[string]int
	cacheHits int
	cacheMiss int
}

func newCountingMetrics() *countingMetrics {
	return &countingMetrics{calls: make(map[string]int)}
}

func (m *countingMetrics) RecordCall(outcome, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[outcome]++
}
func (m *countingMetrics) ObserveCallDuration(time.Duration, string) {}
func (m *countingMetrics) ObserveChunkFanout(int, string)            {}
func (m *countingMetrics) AddBytes(int64, string)                    {}
func (m *countingMetrics) RecordCacheLookup(_, outcome string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch outcome {
	case "hit":
		m.cacheHits++
	case "miss":
		m.cacheMiss++
	}
}

func (m *countingMetrics) callCount(outcome string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[outcome]
}

// pinnedResponse is a small sequenced-response helper so tests can
// model "first call 500, second call 200" without reaching for a
// custom handler on every test.
type pinnedResponse struct {
	status int
	body   string
	netErr bool
	sleep  time.Duration
}

type sequencedHandler struct {
	mu    sync.Mutex
	seq   []pinnedResponse
	calls int
}

func (s *sequencedHandler) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	idx := s.calls
	s.calls++
	if idx >= len(s.seq) {
		s.mu.Unlock()
		http.Error(w, "no response pinned", http.StatusInternalServerError)
		return
	}
	pr := s.seq[idx]
	s.mu.Unlock()

	if pr.sleep > 0 {
		select {
		case <-time.After(pr.sleep):
		case <-r.Context().Done():
			return
		}
	}
	if pr.netErr {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "cannot hijack", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = conn.Close()
		return
	}
	w.WriteHeader(pr.status)
	_, _ = io.WriteString(w, pr.body)
}

// ---- TestSplitForPII parity with Python ----------------------------------

func TestPII_SplitForPII_ShortInputNotSplit(t *testing.T) {
	got := splitForPII("hello world", 1000)
	if len(got) != 1 || got[0] != "hello world" {
		t.Fatalf("expected single chunk 'hello world', got %#v", got)
	}
}

func TestPII_SplitForPII_EmptyInputReturnsEmpty(t *testing.T) {
	got := splitForPII("", 1000)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %#v", got)
	}
}

func TestPII_SplitForPII_NegativeMaxReturnsWholeInput(t *testing.T) {
	got := splitForPII("hello", -1)
	if len(got) != 1 || got[0] != "hello" {
		t.Fatalf("negative max: got %#v", got)
	}
	got = splitForPII("hello", 0)
	if len(got) != 1 || got[0] != "hello" {
		t.Fatalf("zero max: got %#v", got)
	}
}

// ---- TestPIIClient basic paths ------------------------------------------

func TestPIIClient_AnonymizeSuccess(t *testing.T) {
	var captured [][]byte
	var mu sync.Mutex
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		captured = append(captured, body)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"text":"<PERSON> lives in <LOCATION>"}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, nil)
	out, err := c.Anonymize(context.Background(), "John Smith lives in NYC", "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != "<PERSON> lives in <LOCATION>" {
		t.Fatalf("unexpected output: %q", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 1 {
		t.Fatalf("expected exactly 1 downstream call, got %d", len(captured))
	}
	var body map[string]string
	_ = json.Unmarshal(captured[0], &body)
	if body["text"] != "John Smith lives in NYC" {
		t.Fatalf("downstream received wrong text: %q", body["text"])
	}
}

func TestPIIClient_AnonymizeEmptyInputSkipsCall(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.WriteString(w, `{"text":""}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, nil)
	out, err := c.Anonymize(context.Background(), "", "")
	if err != nil || out != "" {
		t.Fatalf("empty input: got (%q, %v), want ('', nil)", out, err)
	}
	if n := atomic.LoadInt32(&calls); n != 0 {
		t.Fatalf("expected 0 downstream calls, got %d", n)
	}
}

func TestPIIClient_5xxFailOpenReturnsOriginal(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
	})
	out, err := c.Anonymize(context.Background(), "original text", "")
	if err != nil || out != "original text" {
		t.Fatalf("fail-open 5xx: got (%q, %v), want ('original text', nil)", out, err)
	}
}

func TestPIIClient_5xxFailClosedRaises(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = true
	})
	_, err := c.Anonymize(context.Background(), "original text", "")
	var piiErr *PIIServiceError
	if !errors.As(err, &piiErr) {
		t.Fatalf("fail-closed 5xx: expected *PIIServiceError, got %T: %v", err, err)
	}
	if piiErr.Outcome != string(piiOutcomeHTTPError) {
		t.Fatalf("unexpected outcome %q", piiErr.Outcome)
	}
}

func TestPIIClient_NetworkErrorFailOpen(t *testing.T) {
	sh := &sequencedHandler{seq: []pinnedResponse{{netErr: true}}}
	url, stop := newPIITestServer(t, sh.handle)
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
	})
	out, err := c.Anonymize(context.Background(), "secret text", "")
	if err != nil || out != "secret text" {
		t.Fatalf("fail-open net err: got (%q, %v), want ('secret text', nil)", out, err)
	}
}

func TestPIIClient_NetworkErrorFailClosed(t *testing.T) {
	sh := &sequencedHandler{seq: []pinnedResponse{{netErr: true}}}
	url, stop := newPIITestServer(t, sh.handle)
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = true
	})
	_, err := c.Anonymize(context.Background(), "secret text", "")
	var piiErr *PIIServiceError
	if !errors.As(err, &piiErr) {
		t.Fatalf("fail-closed net err: expected *PIIServiceError, got %T", err)
	}
}

func TestPIIClient_InvalidJSONFailOpen(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `not json {{{`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, nil)
	out, err := c.Anonymize(context.Background(), "payload", "")
	if err != nil || out != "payload" {
		t.Fatalf("invalid-json fail-open: got (%q, %v), want ('payload', nil)", out, err)
	}
}

func TestPIIClient_MissingTextFieldFallsBackToInput(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"stats":{}}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, nil)
	out, err := c.Anonymize(context.Background(), "payload", "")
	if err != nil || out != "payload" {
		t.Fatalf("missing text: got (%q, %v), want ('payload', nil)", out, err)
	}
}

func TestPIIClient_AnonymizeLongInputChunks(t *testing.T) {
	var received []string
	var mu sync.Mutex
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]string
		_ = json.Unmarshal(body, &env)
		mu.Lock()
		received = append(received, env["text"])
		mu.Unlock()
		out := strings.ReplaceAll(env["text"], "secret", "<REDACTED>")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"text":`+mustJSONString(out)+`}`)
	})
	defer stop()

	text := "secret one\n\nsecret two\n\nsecret three"
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.MaxChars = 15
	})
	out, err := c.Anonymize(context.Background(), text, "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) < 2 {
		t.Fatalf("expected >=2 chunks, got %d: %#v", len(received), received)
	}
	if !strings.Contains(out, "<REDACTED>") {
		t.Fatalf("missing <REDACTED> in %q", out)
	}
	if strings.Contains(out, "secret") {
		t.Fatalf("raw 'secret' still present in %q", out)
	}
	// Split order is preserved in the client; arrival order is not
	// (handlers run concurrently). Assert set equality against
	// splitForPII directly to prove the splitter is lossless.
	wantChunks := splitForPII(text, 15)
	if !sameMultisetOfStrings(received, wantChunks) {
		t.Fatalf("received chunks != splitForPII: got=%#v want=%#v", received, wantChunks)
	}
}

// sameMultisetOfStrings returns true iff a and b contain the same
// strings with the same multiplicity.
func sameMultisetOfStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, s := range a {
		counts[s]++
	}
	for _, s := range b {
		counts[s]--
		if counts[s] < 0 {
			return false
		}
	}
	return true
}

func TestPIIClient_URL(t *testing.T) {
	c := newPIIClientForTest(t, "http://fake-pii/anonymize", nil)
	if c.URL() != "http://fake-pii/anonymize" {
		t.Fatalf("URL() = %q", c.URL())
	}
}

func TestPIIClient_4xxFailOpen(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	defer stop()
	c := newPIIClientForTest(t, url, nil)
	out, err := c.Anonymize(context.Background(), "input", "")
	if err != nil || out != "input" {
		t.Fatalf("4xx fail-open: got (%q, %v), want ('input', nil)", out, err)
	}
}

func TestPIIClient_TimeoutFailClosedRaises(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = io.WriteString(w, `{"text":"x"}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.Timeout = 20 * time.Millisecond
		cfg.FailClosed = true
	})
	_, err := c.Anonymize(context.Background(), "input", "")
	var piiErr *PIIServiceError
	if !errors.As(err, &piiErr) {
		t.Fatalf("expected PIIServiceError, got %T: %v", err, err)
	}
	if piiErr.Outcome != string(piiOutcomeTimeout) {
		t.Fatalf("expected outcome=%q got %q", piiOutcomeTimeout, piiErr.Outcome)
	}
}

// ---- TestPIIClientParallelChunking --------------------------------------

func TestPIIClient_PeakConcurrencyRespectsSemaphore(t *testing.T) {
	var current, peak int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&current, 1)
		for {
			prev := atomic.LoadInt32(&peak)
			if cur <= prev || atomic.CompareAndSwapInt32(&peak, prev, cur) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&current, -1)

		body, _ := io.ReadAll(r.Body)
		var env map[string]string
		_ = json.Unmarshal(body, &env)
		_, _ = io.WriteString(w, `{"text":`+mustJSONString(env["text"]+"_ok")+`}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.MaxChars = 4
		cfg.MaxParallelChunks = 2
	})
	text := strings.Repeat("a", 4) + strings.Repeat("b", 4) + strings.Repeat("c", 4) +
		strings.Repeat("d", 4) + strings.Repeat("e", 4)
	if _, err := c.Anonymize(context.Background(), text, ""); err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	p := atomic.LoadInt32(&peak)
	if p > 2 {
		t.Fatalf("peak > 2: %d", p)
	}
	if p < 2 {
		t.Fatalf("expected peak >=2 (real parallelism), got %d", p)
	}
}

func TestPIIClient_ChunksConcatenatedInOrder(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]string
		_ = json.Unmarshal(body, &env)
		// Vary latency by first character so later letters return first.
		switch {
		case strings.HasPrefix(env["text"], "a"):
			time.Sleep(25 * time.Millisecond)
		case strings.HasPrefix(env["text"], "b"):
			time.Sleep(10 * time.Millisecond)
		}
		_, _ = io.WriteString(w, `{"text":`+mustJSONString("<"+env["text"]+">")+`}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.MaxChars = 4
		cfg.MaxParallelChunks = 4
	})
	text := strings.Repeat("a", 4) + strings.Repeat("b", 4) + strings.Repeat("c", 4)
	out, err := c.Anonymize(context.Background(), text, "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != "<aaaa><bbbb><cccc>" {
		t.Fatalf("out-of-order chunks: %q", out)
	}
}

func TestPIIClient_ChunkFailurePropagatesUnderFailClosed(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 2 {
			hj, _ := w.(http.Hijacker)
			conn, _, _ := hj.Hijack()
			_ = conn.Close()
			return
		}
		_, _ = io.WriteString(w, `{"text":"<OK>"}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.MaxChars = 4
		cfg.MaxParallelChunks = 4
		cfg.FailClosed = true
	})
	text := strings.Repeat("a", 4) + strings.Repeat("b", 4) + strings.Repeat("c", 4) + strings.Repeat("d", 4)
	_, err := c.Anonymize(context.Background(), text, "")
	var piiErr *PIIServiceError
	if !errors.As(err, &piiErr) {
		t.Fatalf("expected fail-closed PIIServiceError, got %T: %v", err, err)
	}
}

func TestPIIClient_SemaphoreClampedToMinimumOne(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var env map[string]string
		_ = json.Unmarshal(body, &env)
		_, _ = io.WriteString(w, `{"text":`+mustJSONString(strings.ToUpper(env["text"]))+`}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.MaxChars = 4
		cfg.MaxParallelChunks = 0
	})
	out, err := c.Anonymize(context.Background(), strings.Repeat("a", 4)+strings.Repeat("b", 4), "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != "AAAABBBB" {
		t.Fatalf("sequential fallback wrong output: %q", out)
	}
}

// ---- TestPIIClientCache --------------------------------------------------

func TestPIIClient_SecondCallIsCacheHit(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	})
	defer stop()

	cache := NewContentFilterCache(ContentFilterCacheConfig{MaxEntries: 16, TTL: time.Minute})
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.Cache = cache
	})
	out1, err1 := c.Anonymize(context.Background(), "hello world", "")
	out2, err2 := c.Anonymize(context.Background(), "hello world", "")
	if err1 != nil || err2 != nil {
		t.Fatalf("Anonymize err: %v / %v", err1, err2)
	}
	if out1 != "<REDACTED>" || out2 != "<REDACTED>" {
		t.Fatalf("unexpected outputs: %q / %q", out1, out2)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected exactly 1 downstream call (second was cache hit), got %d", n)
	}
}

func TestPIIClient_DifferentContextIsAMiss(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	})
	defer stop()

	cache := NewContentFilterCache(ContentFilterCacheConfig{MaxEntries: 16, TTL: time.Minute})
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.Cache = cache
	})
	_, _ = c.Anonymize(context.Background(), "hello", "ctx_a")
	_, _ = c.Anonymize(context.Background(), "hello", "ctx_b")
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("different contexts must not share cache: calls=%d want=2", n)
	}
}

func TestPIIClient_TTLExpiryForcesRefetch(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	})
	defer stop()

	var nowMu sync.Mutex
	now := time.Unix(0, 0)
	advanceNow := func(d time.Duration) {
		nowMu.Lock()
		now = now.Add(d)
		nowMu.Unlock()
	}
	readNow := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	}
	cache := NewContentFilterCacheWithClock(
		ContentFilterCacheConfig{MaxEntries: 16, TTL: 10 * time.Second},
		readNow,
	)
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.Cache = cache
	})
	_, _ = c.Anonymize(context.Background(), "hello", "")
	advanceNow(11 * time.Second)
	_, _ = c.Anonymize(context.Background(), "hello", "")
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("TTL expiry must force refetch: calls=%d want=2", n)
	}
}

func TestPIIClient_CacheAbsentMeansEveryCallHitsNetwork(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.WriteString(w, `{"text":"<REDACTED>"}`)
	})
	defer stop()

	c := newPIIClientForTest(t, url, nil)
	for i := 0; i < 3; i++ {
		_, _ = c.Anonymize(context.Background(), "hello", "")
	}
	if n := atomic.LoadInt32(&calls); n != 3 {
		t.Fatalf("no-cache: expected 3 downstream calls, got %d", n)
	}
}

// ---- TestPIIClientCircuitBreaker ----------------------------------------

func TestPIIClient_OpenCircuitShortCircuitsFailOpen(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer stop()

	var now time.Time
	clock := func() time.Time { return now }
	breaker := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 2, ResetTimeout: 30 * time.Second},
		clock, quietPIILogger(), nil)
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
		cfg.Breaker = breaker
	})
	if out, _ := c.Anonymize(context.Background(), "a", ""); out != "a" {
		t.Fatalf("first fail-open: %q", out)
	}
	if out, _ := c.Anonymize(context.Background(), "b", ""); out != "b" {
		t.Fatalf("second fail-open: %q", out)
	}
	if breaker.State() != CircuitOpen {
		t.Fatalf("expected OPEN after 2 failures, got %v", breaker.State())
	}
	before := atomic.LoadInt32(&calls)
	if out, _ := c.Anonymize(context.Background(), "c", ""); out != "c" {
		t.Fatalf("short-circuit fail-open: %q", out)
	}
	if n := atomic.LoadInt32(&calls) - before; n != 0 {
		t.Fatalf("open breaker must suppress HTTP; saw %d extra calls", n)
	}
}

func TestPIIClient_OpenCircuitRaisesUnderFailClosed(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	defer stop()

	var now time.Time
	breaker := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 2, ResetTimeout: 30 * time.Second},
		func() time.Time { return now }, quietPIILogger(), nil)
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = true
		cfg.Breaker = breaker
	})
	for i := 0; i < 2; i++ {
		if _, err := c.Anonymize(context.Background(), "x", ""); err == nil {
			t.Fatalf("expected fail-closed error, got nil (i=%d)", i)
		}
	}
	if breaker.State() != CircuitOpen {
		t.Fatalf("expected OPEN after 2 failures, got %v", breaker.State())
	}
	_, err := c.Anonymize(context.Background(), "c", "")
	var piiErr *PIIServiceError
	if !errors.As(err, &piiErr) {
		t.Fatalf("expected PIIServiceError on open breaker, got %T: %v", err, err)
	}
	if piiErr.Outcome != string(piiOutcomeCircuitOpen) {
		t.Fatalf("expected outcome=circuit_open, got %q", piiErr.Outcome)
	}
}

func TestPIIClient_BreakerClosesAgainAfterHalfOpenProbe(t *testing.T) {
	var badLeft int32 = 2
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		if atomic.LoadInt32(&badLeft) > 0 {
			atomic.AddInt32(&badLeft, -1)
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"text":"<OK>"}`)
	})
	defer stop()

	var now time.Time
	clock := func() time.Time { return now }
	breaker := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 2, ResetTimeout: 30 * time.Second},
		clock, quietPIILogger(), nil)
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
		cfg.Breaker = breaker
	})
	_, _ = c.Anonymize(context.Background(), "a", "")
	_, _ = c.Anonymize(context.Background(), "b", "")
	if breaker.State() != CircuitOpen {
		t.Fatalf("expected OPEN, got %v", breaker.State())
	}
	// Before cooldown: still open.
	now = now.Add(10 * time.Second)
	_, _ = c.Anonymize(context.Background(), "c", "")
	if breaker.State() != CircuitOpen {
		t.Fatalf("pre-cooldown state changed: %v", breaker.State())
	}
	// After cooldown: probe succeeds, closes.
	now = now.Add(21 * time.Second)
	out, err := c.Anonymize(context.Background(), "d", "")
	if err != nil {
		t.Fatalf("half-open probe err: %v", err)
	}
	if out != "<OK>" {
		t.Fatalf("half-open probe out: %q", out)
	}
	if breaker.State() != CircuitClosed {
		t.Fatalf("breaker should be CLOSED after successful probe, got %v", breaker.State())
	}
}

func TestPIIClient_4xxDoesTripBreaker(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	})
	defer stop()

	var now time.Time
	breaker := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 3, ResetTimeout: 30 * time.Second},
		func() time.Time { return now }, quietPIILogger(), nil)
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
		cfg.Breaker = breaker
	})
	for i := 0; i < 3; i++ {
		_, _ = c.Anonymize(context.Background(), "x", "")
	}
	if breaker.State() != CircuitOpen {
		t.Fatalf("4xx failures must trip breaker in current policy: state=%v", breaker.State())
	}
}

func TestPIIClient_SuccessResetsFailureCounter(t *testing.T) {
	sh := &sequencedHandler{seq: []pinnedResponse{
		{status: 500, body: ""},
		{status: 200, body: `{"text":"<OK>"}`},
		{status: 500, body: ""},
		{status: 200, body: `{"text":"<OK>"}`},
		{status: 500, body: ""},
		{status: 500, body: ""},
	}}
	url, stop := newPIITestServer(t, sh.handle)
	defer stop()

	var now time.Time
	breaker := NewCircuitBreakerWithClock("pii",
		CircuitBreakerConfig{FailureThreshold: 3, ResetTimeout: 30 * time.Second},
		func() time.Time { return now }, quietPIILogger(), nil)
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.FailClosed = false
		cfg.Breaker = breaker
	})
	for i := 0; i < 4; i++ {
		_, _ = c.Anonymize(context.Background(), "x", "")
	}
	if breaker.State() != CircuitClosed {
		t.Fatalf("success should have reset counter; state=%v", breaker.State())
	}
	for i := 0; i < 2; i++ {
		_, _ = c.Anonymize(context.Background(), "y", "")
	}
	if breaker.State() != CircuitClosed {
		t.Fatalf("2 consecutive fails < threshold should not trip; state=%v", breaker.State())
	}
}

// ---- fail-open / fail-closed policy matrix (HANDOFF §4.4) ---------------

// TestPIIClient_FailurePolicyMatrix exhausts the 8-row decision table
// from HANDOFF §4.4 pinning outcome-per-cause under each policy. The
// table is written inline (not as a data structure) to keep the
// assertions visually grep-able in review.
func TestPIIClient_FailurePolicyMatrix(t *testing.T) {
	for _, row := range []struct {
		name       string
		failClosed bool
		handler    piiHandler
		wantErr    bool
		outcomeHit string
	}{
		{
			name:       "5xx_fail_open_returns_original",
			failClosed: false,
			handler:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
			outcomeHit: string(piiOutcomeHTTPError),
		},
		{
			name:       "5xx_fail_closed_raises",
			failClosed: true,
			handler:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 500) },
			wantErr:    true,
			outcomeHit: string(piiOutcomeHTTPError),
		},
		{
			name:       "4xx_fail_open_returns_original",
			failClosed: false,
			handler:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 400) },
			outcomeHit: string(piiOutcomeHTTPError),
		},
		{
			name:       "4xx_fail_closed_raises",
			failClosed: true,
			handler:    func(w http.ResponseWriter, _ *http.Request) { http.Error(w, "x", 400) },
			wantErr:    true,
			outcomeHit: string(piiOutcomeHTTPError),
		},
		{
			name:       "decode_fail_open_returns_original",
			failClosed: false,
			handler:    func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "not json") },
			outcomeHit: string(piiOutcomeDecodeError),
		},
		{
			name:       "decode_fail_closed_raises",
			failClosed: true,
			handler:    func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "not json") },
			wantErr:    true,
			outcomeHit: string(piiOutcomeDecodeError),
		},
		{
			name:       "success_fail_open",
			failClosed: false,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"text":"<OK>"}`)
			},
			outcomeHit: string(piiOutcomeOK),
		},
		{
			name:       "success_fail_closed",
			failClosed: true,
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, `{"text":"<OK>"}`)
			},
			outcomeHit: string(piiOutcomeOK),
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			url, stop := newPIITestServer(t, row.handler)
			defer stop()
			m := newCountingMetrics()
			c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
				cfg.FailClosed = row.failClosed
				cfg.Observer = m
			})
			_, err := c.Anonymize(context.Background(), "input", "unit")
			if row.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !row.wantErr && err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if n := m.callCount(row.outcomeHit); n == 0 {
				t.Fatalf("expected metric for outcome=%q to increment, got counts=%#v",
					row.outcomeHit, m.calls)
			}
		})
	}
}

// mustJSONString marshals s as a JSON string literal, panicking on
// error — only reached with ASCII-safe test data.
func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
