// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"

	"github.com/envoyproxy/ai-gateway/internal/json"
	"github.com/envoyproxy/ai-gateway/internal/logsafe"
)

// Default client knobs matching the Python sidecar's
// `app/config.py:AppConfig` defaults.
const (
	defaultPIITimeout           = 30 * time.Second
	defaultPIIMaxCharsPerChunk  = 5000
	defaultPIIMaxParallelChunks = 4
)

// piiOutcome is the set of outcome labels emitted on metrics and logs by
// the PII client. Kept as a string type rather than an int enum so the
// values flow straight into the (backend PR C) Prometheus label.
type piiOutcome string

const (
	piiOutcomeOK              piiOutcome = "ok"
	piiOutcomeCacheHit        piiOutcome = "cache_hit"
	piiOutcomeCircuitOpen     piiOutcome = "circuit_open"
	piiOutcomeTimeout         piiOutcome = "timeout"
	piiOutcomeHTTPError       piiOutcome = "http_error"
	piiOutcomeDecodeError     piiOutcome = "decode_error"
	piiOutcomeCanceled        piiOutcome = "canceled"
	piiOutcomePartialRollback piiOutcome = "partial_rollback"
)

// PIIServiceError is the sentinel error returned when the PII service
// cannot be consulted successfully and the client is configured
// fail-closed. Dispatcher handlers translate this into a JSON-RPC
// reject with code -32010.
//
// Parity: mirrors `app/pii_client.py:PIIServiceError`.
type PIIServiceError struct {
	// Outcome is one of the piiOutcome constants — the metrics/log
	// label for the failure class.
	Outcome string
	// Err is the underlying cause (HTTP error, timeout, etc.).
	Err error
}

// Error implements the error interface.
func (e *PIIServiceError) Error() string {
	if e.Err == nil {
		return fmt.Sprintf("pii service unavailable: %s", e.Outcome)
	}
	return fmt.Sprintf("pii service unavailable: %s: %v", e.Outcome, e.Err)
}

// Unwrap lets callers use errors.Is/As to inspect the cause.
func (e *PIIServiceError) Unwrap() error { return e.Err }

// PIIMetrics is the cardinality-safe observer interface the client uses
// to emit counts and durations. Every call is synchronous and on the
// hot path so implementations must not block.
//
// The default observer is a no-op; PR C wires this to the OTel registry
// so the historical Prometheus names from HANDOFF §4.6 are preserved.
type PIIMetrics interface {
	// RecordCall increments pii_calls_total{outcome,context}.
	RecordCall(outcome, piiContext string)
	// ObserveCallDuration records pii_call_duration_seconds{context}.
	ObserveCallDuration(d time.Duration, piiContext string)
	// ObserveChunkFanout records pii_chunks_total{context} — the
	// number of chunks a single Anonymize call fanned out into.
	ObserveChunkFanout(chunks int, piiContext string)
	// AddBytes adds to pii_bytes_total{context} (UTF-8 bytes sent).
	AddBytes(n int64, piiContext string)
	// RecordCacheLookup increments cache_lookups_total{cache,outcome}
	// with outcome∈{"hit","miss"} and cache="pii".
	RecordCacheLookup(cache, outcome string)
}

// PIIHedgeMetrics is an optional extension for [PIIMetrics]
// implementations that want to observe L19 hedging behavior. The
// client discovers it via a type-assertion so existing observers
// that do not opt in stay compatible.
//
// RecordHedgeFired fires every time a hedge request is issued. In
// steady state this should be rare (HedgeAfter ≈ p95 latency means
// ~5% of requests fire a hedge). A sudden spike indicates the
// primary path is sagging at the tail.
//
// RecordHedgeWin fires every time a hedge request returns the
// winning response. A healthy system has `hedge_fired` high and
// `hedge_win` low — hedges are issued but rarely needed. `hedge_fired`
// ≈ `hedge_win` indicates HedgeAfter is too aggressive (the primary
// is never given enough time to finish).
type PIIHedgeMetrics interface {
	RecordHedgeFired(piiContext string)
	RecordHedgeWin(piiContext string)
}

// noopPIIMetrics is the zero-value observer.
type noopPIIMetrics struct{}

func (noopPIIMetrics) RecordCall(string, string)                 {}
func (noopPIIMetrics) ObserveCallDuration(time.Duration, string) {}
func (noopPIIMetrics) ObserveChunkFanout(int, string)            {}
func (noopPIIMetrics) AddBytes(int64, string)                    {}
func (noopPIIMetrics) RecordCacheLookup(string, string)          {}
func (noopPIIMetrics) RecordHedgeFired(string)                   {}
func (noopPIIMetrics) RecordHedgeWin(string)                     {}

// PIIClientConfig bundles the knobs NewPIIClient needs. All fields are
// validated/defaulted inside NewPIIClient so callers can pass a zero-
// valued struct and get a working client against URL only.
type PIIClientConfig struct {
	// HTTPClient is the underlying HTTP client. Required.
	HTTPClient *http.Client
	// URL is the absolute POST target for the /anonymize endpoint.
	// Required.
	URL string
	// Timeout is the per-chunk HTTP call timeout.
	// Defaults to 30s when zero. Timeouts shorter than 1ms are
	// rejected to protect against config copy-paste mistakes.
	Timeout time.Duration
	// HedgeAfter, when > 0, enables request hedging (L19): after
	// this duration without a response from the primary request
	// the client fires a second ("hedge") request in parallel.
	// Whichever response arrives first wins and the loser is
	// canceled. 0 disables hedging (default).
	//
	// Reasonable values are near the PII service's p95 latency so
	// hedges only fire on tail-latency outliers, not every call.
	// Too small doubles load; too large provides no benefit.
	//
	// Hedging is bypassed when Timeout < 2 * HedgeAfter because
	// otherwise the hedge has no useful time window to win.
	HedgeAfter time.Duration
	// FailClosed controls what happens when the PII service fails.
	// When true, failures return *PIIServiceError. When false, the
	// original text is returned and a structured warn log is emitted.
	FailClosed bool
	// MaxChars bounds the maximum code-point length of a single
	// request body to /anonymize. Inputs longer than this are split
	// by splitForPII and fanned out in parallel. Defaults to 5000.
	MaxChars int
	// MaxParallelChunks caps how many chunks of a single Anonymize
	// call may be in flight concurrently. Values <1 are clamped to 1
	// so the pipeline always progresses. Defaults to 4.
	MaxParallelChunks int
	// Cache, when set, is consulted before every network call and
	// populated on success. Keyed on SHA-256(context + "\x00" + text).
	Cache *ContentFilterCache
	// Breaker, when set, opens on repeated failures and short-circuits
	// subsequent calls until the reset timeout elapses.
	Breaker *CircuitBreaker
	// OutboundHeaders, when set, is consulted per-request to derive
	// extra headers (typically trace context). It is invoked with the
	// call's context so callers can plug traceparent extraction.
	OutboundHeaders func(context.Context) http.Header
	// Observer receives metric events. nil means no-op.
	Observer PIIMetrics
	// Logger is the slog logger for structured warnings. nil means a
	// discard logger. The client never emits raw text to this logger
	// (see logsafe.Redact); it only emits lengths and outcomes.
	Logger *slog.Logger
	// AuditLogger, when set, receives a [RedactionAuditEvent] for
	// every successful redaction and every fail-open passthrough. It
	// is routed to a separate sink (usually a dedicated audit file)
	// so compliance retention can differ from operational logs. nil
	// means "no audit stream" — events are simply not emitted.
	AuditLogger RedactionAuditLogger
	// Route, Backend, Tool are optional default labels attached to
	// every audit event emitted by this client instance. Call sites
	// that already know these labels can pass them through the
	// existing piiContext string, but for dispatchers with a single
	// stable identity (e.g. a per-route client) these fields are the
	// cheaper route.
	Route   string
	Backend string
	Tool    string
}

// PIIClient anonymizes text through a GPU-backed PII service with
// optional caching, circuit breaking, and bounded parallel chunking.
//
// Parity: mirrors app/pii_client.py:PIIClient. The Go version uses
// errgroup+semaphore for the chunk fan-out (vs asyncio.gather+Semaphore
// in Python) but preserves the exact same public contract: ordered
// concatenation of per-chunk redactions, fail-open returns original
// text, fail-closed raises PIIServiceError, empty input skips the
// network call.
//
// The client is safe for concurrent use by many goroutines and does not
// hold a per-call lock in the hot path.
type PIIClient struct {
	httpClient        *http.Client
	url               string
	timeout           time.Duration
	hedgeAfter        time.Duration
	failClosed        bool
	maxChars          int
	maxParallelChunks int
	cache             *ContentFilterCache
	breaker           *CircuitBreaker
	outboundHeaders   func(context.Context) http.Header
	observer          PIIMetrics
	hedgeMetrics      PIIHedgeMetrics // nil if Observer does not implement it
	logger            *slog.Logger
	audit             RedactionAuditLogger
	defaultRoute      string
	defaultBackend    string
	defaultTool       string
}

// NewPIIClient validates cfg, applies defaults, and returns a ready-to-
// use client. Returns an error if URL or HTTPClient is missing. cfg is
// taken by pointer to avoid copying the 104-byte config struct; the
// caller's cfg is not mutated because we work on a local copy below.
func NewPIIClient(cfgIn *PIIClientConfig) (*PIIClient, error) {
	if cfgIn == nil {
		return nil, errors.New("PIIClientConfig is required")
	}
	cfg := *cfgIn
	if cfg.HTTPClient == nil {
		return nil, errors.New("PIIClientConfig.HTTPClient is required")
	}
	if cfg.URL == "" {
		return nil, errors.New("PIIClientConfig.URL is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultPIITimeout
	}
	if cfg.Timeout < time.Millisecond {
		return nil, fmt.Errorf("PIIClientConfig.Timeout %v is too short; minimum is 1ms", cfg.Timeout)
	}
	if cfg.MaxChars <= 0 {
		cfg.MaxChars = defaultPIIMaxCharsPerChunk
	}
	// Clamp to 1 — Python does the same so a misconfigured 0 never
	// silently disables redaction (which would be a PII leak).
	if cfg.MaxParallelChunks < 1 {
		cfg.MaxParallelChunks = 1
	}
	if cfg.Observer == nil {
		cfg.Observer = noopPIIMetrics{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.AuditLogger == nil {
		cfg.AuditLogger = NoopRedactionAuditLogger{}
	}
	// L19: reject HedgeAfter configs that cannot race meaningfully.
	// The hedge must have at least HedgeAfter to complete before
	// the call-level timeout expires, so 2*HedgeAfter must fit in
	// Timeout. If not, we silently disable hedging rather than
	// fail-bootstrap — this is a soft deployment mistake, not a
	// programming error.
	if cfg.HedgeAfter > 0 && cfg.Timeout < 2*cfg.HedgeAfter {
		cfg.HedgeAfter = 0
	}
	c := &PIIClient{
		httpClient:        cfg.HTTPClient,
		url:               cfg.URL,
		timeout:           cfg.Timeout,
		hedgeAfter:        cfg.HedgeAfter,
		failClosed:        cfg.FailClosed,
		maxChars:          cfg.MaxChars,
		maxParallelChunks: cfg.MaxParallelChunks,
		cache:             cfg.Cache,
		breaker:           cfg.Breaker,
		outboundHeaders:   cfg.OutboundHeaders,
		observer:          cfg.Observer,
		logger:            cfg.Logger,
		audit:             cfg.AuditLogger,
		defaultRoute:      cfg.Route,
		defaultBackend:    cfg.Backend,
		defaultTool:       cfg.Tool,
	}
	// Cache the hedge observer if the observer opted in. Saves a
	// type assertion on every hedged request.
	if hm, ok := cfg.Observer.(PIIHedgeMetrics); ok {
		c.hedgeMetrics = hm
	}
	return c, nil
}

// URL returns the configured anonymize endpoint (exposed so dispatch
// code can log it and tests can assert against it).
func (c *PIIClient) URL() string { return c.url }

// FailClosed returns whether this client raises on PII service errors.
func (c *PIIClient) FailClosed() bool { return c.failClosed }

// Anonymize sends text through the PII service, splitting into chunks
// when it exceeds MaxChars and fanning out up to MaxParallelChunks
// chunks in parallel.
//
// Empty input short-circuits to "" with no network call.
//
// The piiContext parameter is a metric/cache label (e.g.
// "pii_scan:supportgpt.response"). It partitions the cache so two
// different scan paths cannot share redactions, and tags the
// pii_calls_total counter.
//
// Returns (anonymized, nil) on success or fail-open fallback (original
// text returned). Returns ("", *PIIServiceError) on fail-closed.
// Returns (partial, context.Canceled) if the caller cancels before
// all chunks complete — partial is undefined and callers MUST treat
// this as a failure.
func (c *PIIClient) Anonymize(ctx context.Context, text, piiContext string) (string, error) {
	return c.AnonymizeForRoute(ctx, text, piiContext, "", "")
}

// AnonymizeForRoute is the route-aware variant of [Anonymize]: it folds
// the route + backend labels into the cache-key hash so two different
// routes serving the same backend with the same text never share a
// cache row, even if the caller forgets to encode the route into the
// piiContext string. Empty route or backend disables that extra
// isolation and the behaviour collapses to [Anonymize].
//
// Handlers should use this form whenever they have a FilterRequest in
// hand — it is the cheap isolation guarantee that keeps multi-tenant
// deployments from leaking a redaction across route boundaries.
func (c *PIIClient) AnonymizeForRoute(ctx context.Context, text, piiContext, route, backend string) (string, error) {
	if text == "" {
		return "", nil
	}

	if utf8RuneCount(text) <= c.maxChars {
		out, _, err := c.anonymizeOneDetail(ctx, text, piiContext, route, backend)
		return out, err
	}

	chunks := splitForPII(text, c.maxChars)
	c.observer.ObserveChunkFanout(len(chunks), labelOrDash(piiContext))

	sem := semaphore.NewWeighted(int64(c.maxParallelChunks))
	g, gctx := errgroup.WithContext(ctx)
	results := make([]string, len(chunks))
	failedOpen := make([]bool, len(chunks))
	for i, chunk := range chunks {
		g.Go(func() error {
			return safeGo("pii chunk worker", func() error {
				if err := sem.Acquire(gctx, 1); err != nil {
					return err
				}
				defer sem.Release(1)
				out, fo, err := c.anonymizeOneDetail(gctx, chunk, piiContext, route, backend)
				if err != nil {
					return err
				}
				results[i] = out
				failedOpen[i] = fo
				return nil
			})
		})
	}
	if err := g.Wait(); err != nil {
		return "", err
	}

	// L10 — all-or-nothing under fail-open:
	//
	// `anonymizeOneDetail` returns the original text on fail-open so
	// individual chunks always stay non-nil even under failure. But
	// that yields a hazardous mix: the concatenation can look like
	// "REDACTED-1…<unredacted PII>…REDACTED-3". Downstream services
	// can't distinguish between "all clean" and "partially leaked",
	// so we enforce strict all-or-nothing: if ANY chunk fell open,
	// replace ALL chunks with their originals and emit a dedicated
	// metric so operators can alert on silent rollbacks.
	//
	// Cost is one extra pass over the slice, which is negligible
	// compared to the N parallel network calls we just completed.
	anyFailedOpen := false
	for _, fo := range failedOpen {
		if fo {
			anyFailedOpen = true
			break
		}
	}
	if anyFailedOpen {
		c.observer.RecordCall(string(piiOutcomePartialRollback), labelOrDash(piiContext))
		c.logger.WarnContext(ctx, "pii chunk fan-out partially failed; rolling all chunks back to original text (all-or-nothing)",
			slog.String("pii_context", piiContext),
			slog.Int("total_chunks", len(chunks)),
			slog.Int("failed_open_chunks", countTrue(failedOpen)),
		)
		return joinChunks(chunks), nil
	}
	return joinChunks(results), nil
}

// countTrue is a small helper used by the partial-rollback warning
// log so operators immediately see how many chunks fell open.
func countTrue(b []bool) int {
	n := 0
	for _, v := range b {
		if v {
			n++
		}
	}
	return n
}

// anonymizeOneDetail performs a single /anonymize call against the
// PII backend. In addition to the redacted text it reports whether
// this call fell open (i.e. returned the caller's original text
// because the PII service was unreachable and the client is
// configured fail-open).
//
// The fan-out in [AnonymizeForRoute] uses this flag to roll every
// successful sibling chunk back to its original when any one chunk
// fails open. That prevents the "half-redacted / half-plaintext" leak
// where downstream consumers cannot tell a clean payload from a
// partially-leaked one.
//
// Cache hits, circuit-open fallbacks, and full redactions all report
// `failedOpen=false` when they returned redacted text. Only the code
// path that returned the *caller's input verbatim* because of a
// failure reports `failedOpen=true`.
//
// Caches hits short-circuit; cache misses hit the network and populate
// the cache on success. Circuit-breaker and fail-closed policy are
// enforced here.
func (c *PIIClient) anonymizeOneDetail(ctx context.Context, text, piiContext, route, backend string) (string, bool, error) {
	label := labelOrDash(piiContext)
	c.observer.AddBytes(int64(len(text)), label)

	// 1) Cache check. The tenant form of the cache key includes route
	// and backend so two routes can never share a redaction, even if
	// the caller forgot to encode them into piiContext. When both
	// route and backend are empty, this collapses to the plain
	// (context, text) form — keeping the original test vectors valid
	// for the zero-tenant unit-test path.
	cacheKey := ""
	if c.cache != nil {
		if route == "" && backend == "" {
			cacheKey = ContentFilterCacheKey(piiContext, text)
		} else {
			cacheKey = ContentFilterCacheKeyTenant(piiContext, route, backend, text)
		}
		if cached, ok := c.cache.Get(cacheKey); ok {
			c.observer.RecordCacheLookup("pii", "hit")
			c.observer.RecordCall(string(piiOutcomeCacheHit), label)
			c.emitAudit(ctx, route, backend, piiContext,
				len(text), len(cached), 0, nil,
				string(piiOutcomeCacheHit), false)
			return cached, false, nil
		}
		c.observer.RecordCacheLookup("pii", "miss")
	}

	// 2) Circuit breaker check — do this before we consume any
	// network resource, so an open breaker short-circuits immediately.
	if c.breaker != nil && !c.breaker.Allow() {
		c.observer.RecordCall(string(piiOutcomeCircuitOpen), label)
		if c.failClosed {
			return "", false, &PIIServiceError{
				Outcome: string(piiOutcomeCircuitOpen),
				Err:     errors.New("pii circuit open"),
			}
		}
		c.logger.WarnContext(ctx, "pii circuit open; returning original text (fail-open)",
			slog.String("pii_context", piiContext),
			slog.Int("input_chars", len(text)),
		)
		// Fail-open: audit the passthrough so compliance has a
		// record of the unredacted bytes even when the service was
		// down. OutputChars=0 is the sentinel for "no scrub happened".
		c.emitAudit(ctx, route, backend, piiContext,
			len(text), 0, 0, nil,
			string(piiOutcomeCircuitOpen), true)
		return text, true, nil
	}

	// 3) Network call under a per-chunk deadline. With L19 hedging
	//    enabled we race a second request after HedgeAfter; whoever
	//    responds first wins and the loser is canceled.
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	start := time.Now()
	// L21: hand-rolled `{"text":"..."}` encoder, byte-identical to
	// [json.Marshal](map[string]string{"text": s}) but with zero
	// reflection and zero map allocation. The body byte slice is
	// safe to share across hedged goroutines because each creates
	// its own [bytes.NewReader] (stateful reader over a read-only
	// slice is race-free).
	body := appendPIITextBody(make([]byte, 0, len(text)+16), text)

	var result piiHTTPResult
	if c.hedgeAfter <= 0 {
		result = c.doOneHTTPCall(callCtx, ctx, text, body)
	} else {
		result = c.doHedgedHTTPCall(callCtx, ctx, text, body, label)
	}

	if result.err != nil {
		if errors.Is(result.err, context.Canceled) {
			// Caller-side cancellation is neutral: do not count it
			// as a breaker failure. Downstream cancels cascade
			// during fan-out failure and we must not trip the
			// breaker from our own upstream failures.
			return "", false, context.Canceled
		}
		return c.onFailure(ctx, text, piiContext, route, backend, start, result.err, result.outcome)
	}

	// Success path: record breaker success, populate cache, emit metric.
	if c.breaker != nil {
		c.breaker.RecordSuccess()
	}
	elapsed := time.Since(start)
	c.observer.ObserveCallDuration(elapsed, label)
	c.observer.RecordCall(string(piiOutcomeOK), label)

	anonymized := result.text
	if c.cache != nil && cacheKey != "" {
		c.cache.Put(cacheKey, anonymized)
	}
	c.logger.DebugContext(ctx, "pii anonymized",
		slog.String("pii_context", piiContext),
		slog.Int("input_chars", len(text)),
		slog.Int("output_chars", len(anonymized)),
		slog.Duration("elapsed", elapsed),
		slog.Any("stats", logsafe.Redact(result.stats)),
	)
	c.emitAudit(ctx, route, backend, piiContext,
		len(text), len(anonymized), elapsed, result.stats,
		string(piiOutcomeOK), false)
	return anonymized, false, nil
}

// piiHTTPResult is the structured return of [PIIClient.doOneHTTPCall].
// On success: err==nil, text contains the anonymized text (or the
// caller's original text if the server returned an empty "text"
// field), stats is the optional entity-count map. On failure: err!=nil
// and outcome is the [piiOutcome] to emit. The caller owns applying
// breaker updates, metrics, cache, log, and audit — this function
// stays pure so the hedged caller can race two attempts and pick one.
type piiHTTPResult struct {
	text    string
	stats   map[string]int
	err     error
	outcome piiOutcome
}

// doOneHTTPCall performs a single POST to the PII service. The ctx
// covers the network call; parentCtx is used only to derive outbound
// headers (it must NOT be canceled when the call is canceled — that
// would drop trace context on hedged losers). text is the pre-encoded
// wire body, reused across hedge attempts so we don't pay the encode
// cost twice.
func (c *PIIClient) doOneHTTPCall(ctx context.Context, parentCtx context.Context, text string, body []byte) piiHTTPResult {
	req, reqErr := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if reqErr != nil {
		return piiHTTPResult{err: reqErr, outcome: piiOutcomeHTTPError}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.outboundHeaders != nil {
		for k, vs := range c.outboundHeaders(parentCtx) {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		outcome := piiOutcomeHTTPError
		switch {
		case errors.Is(doErr, context.Canceled):
			return piiHTTPResult{err: doErr, outcome: piiOutcomeCanceled}
		case errors.Is(doErr, context.DeadlineExceeded):
			outcome = piiOutcomeTimeout
		}
		return piiHTTPResult{err: doErr, outcome: outcome}
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return piiHTTPResult{
			err:     fmt.Errorf("pii service HTTP %d", resp.StatusCode),
			outcome: piiOutcomeHTTPError,
		}
	}
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return piiHTTPResult{err: readErr, outcome: piiOutcomeHTTPError}
	}
	var parsed struct {
		Text  string         `json:"text"`
		Stats map[string]int `json:"stats"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return piiHTTPResult{err: err, outcome: piiOutcomeDecodeError}
	}
	// Parity with Python: if the PII service omits "text" we fall
	// back to the original input so a malformed 200 still lets the
	// pipeline progress under fail-open.
	if parsed.Text == "" {
		parsed.Text = text
	}
	return piiHTTPResult{text: parsed.Text, stats: parsed.Stats}
}

// doHedgedHTTPCall races two [PIIClient.doOneHTTPCall] attempts. The
// primary starts immediately; the hedge starts after [PIIClient.hedgeAfter]
// if the primary has not yet returned. The first SUCCESS wins; both
// failures bubble up the earlier failure. Each attempt runs under its
// own cancelable context so the winner can pre-empt the loser without
// touching the call-level context.
func (c *PIIClient) doHedgedHTTPCall(callCtx context.Context, parentCtx context.Context, text string, body []byte, label string) piiHTTPResult {
	primaryCtx, primaryCancel := context.WithCancel(callCtx)
	defer primaryCancel()
	hedgeCtx, hedgeCancel := context.WithCancel(callCtx)
	defer hedgeCancel()

	primaryCh := make(chan piiHTTPResult, 1)
	hedgeCh := make(chan piiHTTPResult, 1)

	go func() { primaryCh <- c.doOneHTTPCall(primaryCtx, parentCtx, text, body) }()

	timer := time.NewTimer(c.hedgeAfter)
	defer timer.Stop()

	// Phase 1: wait for either primary to finish OR the hedge timer
	// to fire. A fast primary returns immediately with no hedge
	// fired.
	select {
	case res := <-primaryCh:
		if res.err == nil {
			return res
		}
		// Primary failed before the hedge timer fired. Fire the
		// hedge now — the service might have been momentarily
		// flaky, not terminally down.
		timer.Stop()
		// fall through into Phase 2 with hedge about to fire.
		c.recordHedgeFired(label)
		go func() { hedgeCh <- c.doOneHTTPCall(hedgeCtx, parentCtx, text, body) }()
		hedge := <-hedgeCh
		if hedge.err != nil {
			// Both failed; return the primary's error (captured
			// first) — dashboards will see the original failure
			// class instead of a secondary one.
			return res
		}
		c.recordHedgeWin(label)
		return hedge
	case <-timer.C:
		c.recordHedgeFired(label)
		go func() { hedgeCh <- c.doOneHTTPCall(hedgeCtx, parentCtx, text, body) }()
	}

	// Phase 2: both attempts are racing; take the first success. If
	// the first finisher errs, wait for the second before giving up.
	first := piiHTTPResult{}
	for i := 0; i < 2; i++ {
		var r piiHTTPResult
		var fromHedge bool
		select {
		case r = <-primaryCh:
		case r = <-hedgeCh:
			fromHedge = true
		}
		if r.err == nil {
			if fromHedge {
				c.recordHedgeWin(label)
			}
			return r
		}
		if i == 0 {
			first = r
		}
	}
	// Both failed. Return the first failure so breaker classification
	// is stable.
	return first
}

// recordHedgeFired is a nil-safe wrapper for the optional hedge metric.
func (c *PIIClient) recordHedgeFired(label string) {
	if c.hedgeMetrics != nil {
		c.hedgeMetrics.RecordHedgeFired(label)
	}
}

// recordHedgeWin is a nil-safe wrapper for the optional hedge metric.
func (c *PIIClient) recordHedgeWin(label string) {
	if c.hedgeMetrics != nil {
		c.hedgeMetrics.RecordHedgeWin(label)
	}
}

// onFailure captures the shared tail of every failure branch: record
// the breaker failure, emit metrics, log safely (never the raw text),
// and then either raise PIIServiceError (fail-closed) or return the
// original text (fail-open).
//
// The middle return value is the `failedOpen` flag — true iff this
// call is returning the caller's original text because fail-open was
// configured and the backend was unreachable. [AnonymizeForRoute] uses
// that flag to enforce L10 all-or-nothing chunk semantics. Fail-closed
// returns (zero, false, err) because no text is emitted at all.
func (c *PIIClient) onFailure(
	ctx context.Context,
	text, piiContext, route, backend string,
	start time.Time,
	cause error,
	outcome piiOutcome,
) (string, bool, error) {
	if c.breaker != nil {
		c.breaker.RecordFailure()
	}
	label := labelOrDash(piiContext)
	elapsed := time.Since(start)
	c.observer.ObserveCallDuration(elapsed, label)
	c.observer.RecordCall(string(outcome), label)

	c.logger.WarnContext(ctx, "pii service failed",
		slog.String("url", c.url),
		slog.String("pii_context", piiContext),
		slog.Int("input_chars", len(text)),
		slog.Duration("elapsed", elapsed),
		slog.Bool("fail_closed", c.failClosed),
		slog.String("outcome", string(outcome)),
		slog.String("err", cause.Error()),
	)

	if c.failClosed {
		return "", false, &PIIServiceError{Outcome: string(outcome), Err: cause}
	}
	// Fail-open passthrough: record the leak-class event so auditors
	// see *which* requests escaped redaction. This is the single most
	// important signal on the L13 stream — compliance teams want to
	// be able to answer "did any PII pass through unredacted between
	// 13:00 and 14:00 yesterday?" with a direct query, not a log hunt.
	c.emitAudit(ctx, route, backend, piiContext,
		len(text), 0, elapsed, nil,
		string(outcome), true)
	return text, true, nil
}

// emitAudit funnels one event through the configured audit sink. The
// route/backend/tool fields fall back to the client's default labels
// when the per-call overrides are empty, so callers don't need to
// repeat themselves.
//
// Stats is passed by reference; implementations must not mutate the
// map (copying it here would waste allocations on every redaction).
// Nothing inside mcpproxy writes back to the map after this call, and
// that is a hard invariant — audit sinks in downstream applications
// rely on it.
func (c *PIIClient) emitAudit(
	ctx context.Context,
	route, backend, piiContext string,
	inputChars, outputChars int,
	elapsed time.Duration,
	stats map[string]int,
	outcome string,
	failOpen bool,
) {
	if c.audit == nil {
		return
	}
	if route == "" {
		route = c.defaultRoute
	}
	if backend == "" {
		backend = c.defaultBackend
	}
	c.audit.LogRedaction(ctx, &RedactionAuditEvent{
		Timestamp:   time.Now().UTC(),
		Route:       route,
		Backend:     backend,
		Tool:        c.defaultTool,
		PIIContext:  piiContext,
		InputChars:  inputChars,
		OutputChars: outputChars,
		Stats:       stats,
		Elapsed:     elapsed,
		Outcome:     outcome,
		FailOpen:    failOpen,
	})
}

// labelOrDash mirrors the Python `context or "-"` idiom. Prometheus
// labels cannot be empty without losing the partition, so missing
// context labels flatten to "-".
func labelOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// joinChunks concatenates anonymized chunks in input order. Split into a
// function so tests can assert the join contract independently.
func joinChunks(chunks []string) string {
	// Pre-allocate the exact final buffer size to avoid repeated
	// reallocation on large responses (pathological multi-MB chunking
	// showed up in Python profiling as a hot spot).
	total := 0
	for _, c := range chunks {
		total += len(c)
	}
	var b strings.Builder
	b.Grow(total)
	for _, c := range chunks {
		b.WriteString(c)
	}
	return b.String()
}

// utf8RuneCount counts code points without allocating a []rune copy.
func utf8RuneCount(s string) int { return utf8.RuneCountInString(s) }
