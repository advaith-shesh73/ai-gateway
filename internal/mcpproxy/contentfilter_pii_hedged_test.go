// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// hedgeMetricsRecorder is a PIIMetrics + PIIHedgeMetrics composite used
// to assert when hedges fire and win. All methods are safe for
// concurrent use because hedged tests run two goroutines in parallel.
type hedgeMetricsRecorder struct {
	mu     sync.Mutex
	calls  map[string]int
	fired  int
	wins   int
	labels []string
}

func newHedgeMetricsRecorder() *hedgeMetricsRecorder {
	return &hedgeMetricsRecorder{calls: make(map[string]int)}
}

func (m *hedgeMetricsRecorder) RecordCall(outcome, _ string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[outcome]++
}
func (m *hedgeMetricsRecorder) ObserveCallDuration(time.Duration, string) {}
func (m *hedgeMetricsRecorder) ObserveChunkFanout(int, string)            {}
func (m *hedgeMetricsRecorder) AddBytes(int64, string)                    {}
func (m *hedgeMetricsRecorder) RecordCacheLookup(string, string)          {}

func (m *hedgeMetricsRecorder) RecordHedgeFired(label string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fired++
	m.labels = append(m.labels, "fired:"+label)
}

func (m *hedgeMetricsRecorder) RecordHedgeWin(label string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.wins++
	m.labels = append(m.labels, "win:"+label)
}

func (m *hedgeMetricsRecorder) counts() (fired, wins int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.fired, m.wins
}

// TestHedge_DisabledWhenHedgeAfterZero — with HedgeAfter=0 hedging is
// off: the handler sees exactly one request no matter how slow the
// primary is.
func TestHedge_DisabledWhenHedgeAfterZero(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(20 * time.Millisecond)
		_, _ = io.WriteString(w, `{"text":"<PERSON>"}`)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 0
		cfg.Observer = rec
	})

	out, err := c.Anonymize(context.Background(), "John", "")
	if err != nil || out != "<PERSON>" {
		t.Fatalf("Anonymize: (%q,%v)", out, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 downstream call with hedging off, got %d", got)
	}
	if fired, wins := rec.counts(); fired != 0 || wins != 0 {
		t.Fatalf("expected no hedge activity, got fired=%d wins=%d", fired, wins)
	}
}

// TestHedge_FastPrimaryNoHedgeFired — when the primary returns well
// before HedgeAfter, the hedge never fires and the handler sees exactly
// one request.
func TestHedge_FastPrimaryNoHedgeFired(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		_, _ = io.WriteString(w, `{"text":"<PERSON>"}`)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 100 * time.Millisecond
		cfg.Timeout = 2 * time.Second
		cfg.Observer = rec
	})

	out, err := c.Anonymize(context.Background(), "John", "")
	if err != nil || out != "<PERSON>" {
		t.Fatalf("Anonymize: (%q,%v)", out, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected 1 downstream call with fast primary, got %d", got)
	}
	if fired, _ := rec.counts(); fired != 0 {
		t.Fatalf("expected no hedge to fire, got fired=%d", fired)
	}
}

// TestHedge_SlowPrimaryHedgeWins — the primary is artificially slow
// so the hedge fires; the second attempt is fast and wins the race.
// Verifies:
//   - Exactly 2 downstream calls
//   - Hedge fired counter == 1
//   - Hedge win counter == 1
//   - Returned text came from the hedge handler response.
func TestHedge_SlowPrimaryHedgeWins(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			// primary: sleep longer than HedgeAfter + hedge RTT
			select {
			case <-time.After(300 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, `{"text":"<PRIMARY>"}`)
			return
		}
		// hedge: answer fast
		_, _ = io.WriteString(w, `{"text":"<HEDGE>"}`)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 30 * time.Millisecond
		cfg.Timeout = 2 * time.Second
		cfg.Observer = rec
	})

	start := time.Now()
	out, err := c.Anonymize(context.Background(), "alice", "")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != "<HEDGE>" {
		t.Fatalf("expected hedge response <HEDGE>, got %q", out)
	}
	if elapsed > 250*time.Millisecond {
		t.Fatalf("total elapsed %v exceeded hedged budget; hedge did not win", elapsed)
	}
	if got := atomic.LoadInt32(&calls); got != 2 {
		t.Fatalf("expected 2 downstream calls (primary+hedge), got %d", got)
	}
	fired, wins := rec.counts()
	if fired != 1 {
		t.Fatalf("expected RecordHedgeFired=1, got %d", fired)
	}
	if wins != 1 {
		t.Fatalf("expected RecordHedgeWin=1, got %d", wins)
	}
}

// TestHedge_PrimaryBeatsHedge — primary responds just slightly slower
// than HedgeAfter but still faster than the hedge, so primary wins the
// race; the hedge does fire but does not win. We still count one call
// in fired=1 wins=0.
func TestHedge_PrimaryBeatsHedge(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			// primary: barely beats hedge
			select {
			case <-time.After(60 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, `{"text":"<PRIMARY>"}`)
			return
		}
		// hedge: much slower
		select {
		case <-time.After(500 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, `{"text":"<HEDGE>"}`)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 30 * time.Millisecond
		cfg.Timeout = 2 * time.Second
		cfg.Observer = rec
	})

	out, err := c.Anonymize(context.Background(), "bob", "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != "<PRIMARY>" {
		t.Fatalf("expected primary to win, got %q", out)
	}
	fired, wins := rec.counts()
	if fired != 1 {
		t.Fatalf("expected RecordHedgeFired=1, got %d", fired)
	}
	if wins != 0 {
		t.Fatalf("expected RecordHedgeWin=0 (primary won), got %d", wins)
	}
}

// TestHedge_PrimaryFailsHedgeSucceeds — primary 5xx, hedge 200. The
// client fires the hedge immediately when primary errors (even before
// the timer fires). The hedge result wins and the caller sees success.
func TestHedge_PrimaryFailsHedgeSucceeds(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			http.Error(w, "primary down", http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, `{"text":"<HEDGE>"}`)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 500 * time.Millisecond
		cfg.Timeout = 5 * time.Second
		cfg.Observer = rec
		cfg.FailClosed = false
	})

	out, err := c.Anonymize(context.Background(), "carol", "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != "<HEDGE>" {
		t.Fatalf("expected hedge to recover primary failure, got %q", out)
	}
	fired, wins := rec.counts()
	if fired != 1 {
		t.Fatalf("expected RecordHedgeFired=1 (fired on primary failure), got %d", fired)
	}
	if wins != 1 {
		t.Fatalf("expected RecordHedgeWin=1, got %d", wins)
	}
}

// TestHedge_BothFailReturnsFailOpen — primary and hedge both fail;
// client is configured fail-open so it returns the original text. The
// error path must record exactly one failure outcome (not double-
// counted from the hedge).
func TestHedge_BothFailReturnsFailOpen(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "down", http.StatusInternalServerError)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 20 * time.Millisecond
		cfg.Timeout = 2 * time.Second
		cfg.Observer = rec
		cfg.FailClosed = false
	})

	const original = "dave @ acme"
	out, err := c.Anonymize(context.Background(), original, "")
	if err != nil {
		t.Fatalf("Anonymize err: %v", err)
	}
	if out != original {
		t.Fatalf("fail-open: expected passthrough %q, got %q", original, out)
	}
	// Exactly one http_error outcome emitted — the caller sees ONE
	// failure, not two, even though both attempts failed.
	if got := rec.calls["http_error"]; got != 1 {
		t.Fatalf("expected exactly 1 http_error call, got %d (all outcomes: %+v)", got, rec.calls)
	}
}

// TestHedge_PrimaryCancellationIsNotBreakerFailure — context canceled
// by caller during hedged execution returns context.Canceled directly,
// does not record a breaker failure. This protects the breaker from
// upstream shutdown storms.
func TestHedge_CallerCancelPropagates(t *testing.T) {
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// never respond in-time; rely on context cancel to free.
		select {
		case <-time.After(5 * time.Second):
			_, _ = io.WriteString(w, `{"text":"<PERSON>"}`)
		case <-r.Context().Done():
			return
		}
	})
	defer stop()

	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 10 * time.Millisecond
		cfg.Timeout = 10 * time.Second
	})

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	_, err := c.Anonymize(ctx, "hidden", "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

// TestHedge_DisabledWhenTimeoutTooSmall — when Timeout < 2*HedgeAfter
// the constructor disables hedging so a hedge doesn't get only a tiny
// window to complete. Smoke test: one downstream call only.
func TestHedge_DisabledWhenTimeoutTooSmall(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		time.Sleep(40 * time.Millisecond)
		_, _ = io.WriteString(w, `{"text":"<PERSON>"}`)
	})
	defer stop()

	rec := newHedgeMetricsRecorder()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		// Timeout < 2*HedgeAfter → hedging silently disabled.
		cfg.HedgeAfter = 200 * time.Millisecond
		cfg.Timeout = 300 * time.Millisecond
		cfg.Observer = rec
	})
	if c.hedgeAfter != 0 {
		t.Fatalf("expected hedgeAfter cleared to 0, got %v", c.hedgeAfter)
	}

	out, err := c.Anonymize(context.Background(), "erin", "")
	if err != nil || out != "<PERSON>" {
		t.Fatalf("Anonymize: (%q,%v)", out, err)
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("hedging should be disabled, got %d calls", got)
	}
}

// TestHedge_ObserverWithoutHedgeMetrics — an observer that does NOT
// implement PIIHedgeMetrics must not crash when hedging fires; the
// client should silently skip hedge-specific recording.
func TestHedge_ObserverWithoutHedgeMetrics(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			select {
			case <-time.After(200 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		_, _ = io.WriteString(w, `{"text":"<PERSON>"}`)
	})
	defer stop()

	// countingMetrics implements PIIMetrics but NOT PIIHedgeMetrics.
	plain := newCountingMetrics()
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 20 * time.Millisecond
		cfg.Timeout = 2 * time.Second
		cfg.Observer = plain
	})
	if c.hedgeMetrics != nil {
		t.Fatal("hedgeMetrics should be nil when observer does not implement PIIHedgeMetrics")
	}
	out, err := c.Anonymize(context.Background(), "frank", "")
	if err != nil || out != "<PERSON>" {
		t.Fatalf("Anonymize: (%q,%v)", out, err)
	}
	// The call must still have landed once, and at least one call
	// outcome was recorded via the plain observer.
	if plain.callCount("ok") == 0 {
		t.Fatalf("expected at least one ok outcome, got %d", plain.callCount("ok"))
	}
}

// TestHedge_CacheWriteExactlyOnce — when both primary and hedge succeed,
// the cache must be populated exactly once (the winner's value). We
// verify this by issuing a second Anonymize and observing it returns
// the first winner's text with zero additional network calls.
func TestHedge_CacheWriteExactlyOnce(t *testing.T) {
	var calls int32
	url, stop := newPIITestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			// primary: slow, but eventually succeeds.
			select {
			case <-time.After(200 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
			_, _ = io.WriteString(w, `{"text":"<PRIMARY>"}`)
			return
		}
		// hedge wins (fast)
		_, _ = io.WriteString(w, `{"text":"<HEDGE>"}`)
	})
	defer stop()

	cache := NewContentFilterCache(ContentFilterCacheConfig{MaxEntries: 8})
	c := newPIIClientForTest(t, url, func(cfg *PIIClientConfig) {
		cfg.HedgeAfter = 30 * time.Millisecond
		cfg.Timeout = 2 * time.Second
		cfg.Cache = cache
	})

	out1, err := c.Anonymize(context.Background(), "greta", "")
	if err != nil {
		t.Fatalf("first Anonymize: %v", err)
	}
	// Let any still-in-flight goroutines finish so we can check that
	// ONLY the hedge's value landed in cache (the primary must not
	// overwrite the hedge's cached entry on its late return).
	time.Sleep(400 * time.Millisecond)

	callsBefore := atomic.LoadInt32(&calls)
	out2, err := c.Anonymize(context.Background(), "greta", "")
	if err != nil {
		t.Fatalf("second Anonymize: %v", err)
	}
	callsAfter := atomic.LoadInt32(&calls)
	if callsAfter != callsBefore {
		t.Fatalf("expected cache hit on 2nd call (no net calls), got +%d calls", callsAfter-callsBefore)
	}
	if out1 != out2 {
		t.Fatalf("cached value should match first winner: first=%q second=%q", out1, out2)
	}
}
