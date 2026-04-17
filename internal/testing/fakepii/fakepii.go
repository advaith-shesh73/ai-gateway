// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package fakepii provides an in-process, httptest.Server-backed mock of
// the GPU-backed PII anonymization service used by the content-filter
// sidecar. It exists so unit and concurrency tests can exercise the
// real HTTP paths (timeouts, circuit-breaker tripping, bounded fan-out)
// without talking to a GPU service.
//
// The surface intentionally mirrors the Python reference in
// `panacea-agent/services/aigw-content-filter/tests/e2e/mock_pii.py`:
// same regex-based NER (EMAIL → PERSON → IP → PHONE ordering), same
// `/anonymize` + `/health` protocol, and an `in-flight` counter/peak
// pair so the parallelism-parity tests (reference §7.7.1) can assert
// bounded fan-out.
//
// Note on placement: the handoff doc originally spec'd
// `internal/mcpproxy/testdata/fakepii/`, but Go's toolchain skips any
// directory named `testdata` when compiling packages, which would make
// this helper unimportable. This package lives under `internal/testing/`
// to match the repo's existing test-helper convention (see
// `internal/testing/testotel/`) and remain importable by tests across
// any package in the module.
package fakepii

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// Precompiled regexes — parity with mock_pii.py._{EMAIL,PERSON,PHONE,IP}_RE.
//
// Ordering matters: emails are anonymized first because an email's
// local part contains letter tokens that could otherwise false-match
// the person regex; IPs and phones run on the already-redacted string
// so neither accidentally consumes digits inside an email.
var (
	emailRE  = regexp.MustCompile(`([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})`)
	personRE = regexp.MustCompile(`\b[A-Z][a-z]+(?:\s+[A-Z](?:[a-z]*|\b))\b`)
	phoneRE  = regexp.MustCompile(`\b(?:\+?\d{1,3}[\s\-]?)?(?:\(?\d{3}\)?[\s\-]?)?\d{3}[\s\-]?\d{4}\b`)
	ipRE     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// anonymizeText applies regex NER to text, returning (redacted, stats).
// The counters map omits categories with zero matches to match the
// Python mock's stats contract.
func anonymizeText(text string) (string, map[string]int) {
	if text == "" {
		return text, nil
	}
	var (
		emailN  int
		personN int
		phoneN  int
		ipN     int
	)
	out := emailRE.ReplaceAllStringFunc(text, func(string) string {
		emailN++
		return fmt.Sprintf("<EMAIL_%d>", emailN)
	})
	out = personRE.ReplaceAllStringFunc(out, func(string) string {
		personN++
		return fmt.Sprintf("<PERSON_%d>", personN)
	})
	out = ipRE.ReplaceAllStringFunc(out, func(string) string {
		ipN++
		return fmt.Sprintf("<IP_%d>", ipN)
	})
	out = phoneRE.ReplaceAllStringFunc(out, func(string) string {
		phoneN++
		return fmt.Sprintf("<PHONE_%d>", phoneN)
	})
	stats := map[string]int{}
	if emailN > 0 {
		stats["EMAIL"] = emailN
	}
	if personN > 0 {
		stats["PERSON"] = personN
	}
	if ipN > 0 {
		stats["IP"] = ipN
	}
	if phoneN > 0 {
		stats["PHONE"] = phoneN
	}
	if len(stats) == 0 {
		stats = nil
	}
	return out, stats
}

// Server is the mock PII service. Embed *httptest.Server exposes the
// standard URL/Close surface; the accessor helpers expose live counters
// (“InFlight“, “MaxInFlight“, “CallCount“, “FailureCount“) and
// failure-injection knobs (“SetDelay“, “SetFailure“) so tests can
// drive chaos paths without killing the process.
//
// All methods are goroutine-safe. The accessor methods are safe to call
// from test assertions while requests are in flight.
type Server struct {
	*httptest.Server

	mu            sync.Mutex
	delay         time.Duration
	failureStatus int // 0 means healthy
	callCount     int
	failureCount  int
	inFlight      int
	maxInFlight   int
	lastText      string
}

// New starts a fresh Server backed by httptest.NewServer. The returned
// Server is ready to receive requests; call Close when the test is done.
func New() *Server {
	s := &Server{}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/anonymize", s.handleAnonymize)
	mux.HandleFunc("/_stats", s.handleStats)
	mux.HandleFunc("/_reset", s.handleReset)
	s.Server = httptest.NewServer(mux)
	return s
}

// InFlight returns the instantaneous number of /anonymize handlers
// currently inside the (optionally delayed) processing window. Tests
// can poll this while driving concurrent dispatch to verify that the
// sidecar's chunk semaphore is clamping fan-out.
func (s *Server) InFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inFlight
}

// MaxInFlight returns the peak value of InFlight observed since the
// last Reset (or Server start). Parallelism-parity tests assert this
// is >= 1 and <= MaxParallelParts * MaxParallelChunks.
func (s *Server) MaxInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxInFlight
}

// CallCount returns the total number of /anonymize calls the server
// has seen since the last Reset.
func (s *Server) CallCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.callCount
}

// FailureCount returns the number of /anonymize calls the server has
// answered with a non-2xx response since the last Reset.
func (s *Server) FailureCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failureCount
}

// SetDelay configures how long each subsequent /anonymize handler
// sleeps before returning. Pass 0 to return immediately. Applies to
// all in-flight and future requests: in-flight requests continue to
// observe the previous delay until they wake.
func (s *Server) SetDelay(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = d
}

// SetFailure configures the HTTP status code /anonymize will return
// for every subsequent request. Pass 0 to clear (return to healthy).
// Typical values: 500 to simulate GPU crashes, 429 to simulate
// rate-limiting, 503 to simulate maintenance. Health checks remain
// green regardless — the mock fails only the anonymization path, so
// callers must react to the failed /anonymize call rather than a
// health probe.
func (s *Server) SetFailure(status int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failureStatus = status
}

// Reset clears all counters and resets delay/failure knobs to their
// default (healthy, no delay) state. Use between subtests to restore
// a clean baseline.
func (s *Server) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delay = 0
	s.failureStatus = 0
	s.callCount = 0
	s.failureCount = 0
	s.inFlight = 0
	s.maxInFlight = 0
	s.lastText = ""
}

// --- HTTP handlers ---

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleStats(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	payload := map[string]any{
		"call_count":    s.callCount,
		"failure_count": s.failureCount,
		"in_flight":     s.inFlight,
		"max_in_flight": s.maxInFlight,
		"last_text_len": len(s.lastText),
	}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *Server) handleReset(w http.ResponseWriter, _ *http.Request) {
	s.Reset()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"status":"reset"}`))
}

func (s *Server) handleAnonymize(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.callCount++
	failStatus := s.failureStatus
	delay := s.delay
	s.mu.Unlock()

	if failStatus != 0 {
		s.mu.Lock()
		s.failureCount++
		s.mu.Unlock()
		http.Error(w, fmt.Sprintf(`{"detail":"mock-pii failure %d"}`, failStatus), failStatus)
		return
	}

	var payload struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.mu.Lock()
		s.failureCount++
		s.mu.Unlock()
		http.Error(w, `{"detail":"bad body"}`, http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	s.lastText = payload.Text
	s.inFlight++
	if s.inFlight > s.maxInFlight {
		s.maxInFlight = s.inFlight
	}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.inFlight--
		s.mu.Unlock()
	}()

	if delay > 0 {
		// Respect context cancellation so timeout tests don't have to
		// wait out the entire delay for every fan-out chunk.
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			s.mu.Lock()
			s.failureCount++
			s.mu.Unlock()
			return
		}
	}

	start := time.Now()
	redacted, stats := anonymizeText(payload.Text)
	elapsedMs := float64(time.Since(start).Microseconds()) / 1000.0

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"text":               redacted,
		"stats":              stats,
		"mapping":            map[string]string{},
		"processing_time_ms": elapsedMs,
	})
}
