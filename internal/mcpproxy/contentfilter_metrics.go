// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics is the concrete, Prometheus-backed implementation
// of every observer interface in this package. It registers 14 metric
// vectors with the supplied [prometheus.Registerer]:
//
//  1. pii_calls_total{outcome,context}
//  2. pii_call_duration_seconds{context}
//  3. pii_chunks_total{context}
//  4. pii_bytes_total{context}
//  5. cache_lookups_total{cache,outcome}
//  6. jira_calls_total{outcome,op}
//  7. jira_call_duration_seconds{op}
//  8. mcp_filter_circuit_state{name}
//  9. mcp_filter_circuit_transitions_total{name,from,to}
//
// 10. mcp_filter_decisions_total{route,backend,scope,action}
// 11. mcp_filter_status_total{route,backend,status}
// 12. mcp_filter_inflight{route,backend}
// 13. mcp_filter_queue_depth{stage}
// 14. mcp_filter_worker_panics_total{worker}
//
// The legacy names (pii_*, jira_*, cache_*) are preserved verbatim
// because dashboards and alert rules already reference them; the new
// names use the mcp_filter_ prefix to avoid collisions with unrelated
// subsystems in the gateway process.
//
// The struct does NOT satisfy [PIIMetrics], [JiraMetrics], or
// [BreakerObserver] directly — use [PrometheusMetrics.AsPII],
// [PrometheusMetrics.AsJira], and [PrometheusMetrics.AsBreaker] to get
// interface-compatible adapters. This indirection exists because
// PIIMetrics.RecordCall and JiraMetrics.RecordCall share an identical
// method signature but target different counter_vecs; a single
// implementation cannot satisfy both correctly.
//
// Concurrency: all Prometheus vectors are safe for concurrent use.
// PrometheusMetrics itself owns no mutable state beyond the vectors.
//
// Registration: this constructor uses [prometheus.Registerer.MustRegister]
// internally. If the same metric was registered previously with the same
// registerer, it will panic — callers are expected to build one
// PrometheusMetrics per process (or pass a fresh registry in tests).
type PrometheusMetrics struct {
	// PII observers.
	piiCalls        *prometheus.CounterVec
	piiCallDuration *prometheus.HistogramVec
	piiChunks       *prometheus.HistogramVec
	piiBytes        *prometheus.CounterVec

	// Cache observer (shared across PII + Jira).
	cacheLookups *prometheus.CounterVec

	// Jira observers.
	jiraCalls        *prometheus.CounterVec
	jiraCallDuration *prometheus.HistogramVec

	// Circuit-breaker observers.
	circuitState       *prometheus.GaugeVec
	circuitTransitions *prometheus.CounterVec

	// Filter decision / status observers.
	filterDecisions *prometheus.CounterVec
	filterStatus    *prometheus.CounterVec

	// Saturation gauges.
	filterInflight   *prometheus.GaugeVec
	filterQueueDepth *prometheus.GaugeVec

	// Hot-path safety counter.
	workerPanics *prometheus.CounterVec

	// Cardinality guards (L23). Each guard is per-metric because
	// different metrics have different natural budgets: routes are
	// finite, but tool names can come from client inputs and
	// therefore need a tighter cap. The guards are installed lazily
	// via [PrometheusMetrics.WithCardinalityLimit]; absence means
	// no cap is enforced, matching the original unbounded
	// behaviour. Each guard exposes its own OverflowCount() for
	// alerting.
	decisionGuard *CardinalityGuard
	statusGuard   *CardinalityGuard
	inflightGuard *CardinalityGuard
}

// NewPrometheusMetrics constructs all 14 vectors and registers them
// with reg. Passing nil substitutes [prometheus.DefaultRegisterer]. A
// fresh [prometheus.NewRegistry] should be used in tests.
func NewPrometheusMetrics(reg prometheus.Registerer) *PrometheusMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &PrometheusMetrics{
		piiCalls: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pii_calls_total",
				Help: "Total number of PII anonymize calls by outcome and logical context.",
			},
			[]string{"outcome", "context"},
		),
		piiCallDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pii_call_duration_seconds",
				Help:    "Latency of PII anonymize HTTP calls.",
				Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
			},
			[]string{"context"},
		),
		piiChunks: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "pii_chunks_total",
				Help:    "Number of chunks a single Anonymize request fanned out into.",
				Buckets: prometheus.LinearBuckets(1, 1, 10),
			},
			[]string{"context"},
		),
		piiBytes: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "pii_bytes_total",
				Help: "UTF-8 bytes sent to the PII anonymize endpoint (before any chunking).",
			},
			[]string{"context"},
		),
		cacheLookups: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "cache_lookups_total",
				Help: "Content-filter cache lookups by cache name and outcome (hit/miss).",
			},
			[]string{"cache", "outcome"},
		),
		jiraCalls: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "jira_calls_total",
				Help: "Total number of Jira client calls by outcome and logical op.",
			},
			[]string{"outcome", "op"},
		),
		jiraCallDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "jira_call_duration_seconds",
				Help:    "Latency of Jira HTTP calls.",
				Buckets: prometheus.ExponentialBuckets(0.005, 2, 12),
			},
			[]string{"op"},
		),
		circuitState: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mcp_filter_circuit_state",
				Help: "Current circuit-breaker state (0=closed, 1=half_open, 2=open).",
			},
			[]string{"name"},
		),
		circuitTransitions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mcp_filter_circuit_transitions_total",
				Help: "Circuit-breaker state transitions.",
			},
			[]string{"name", "from", "to"},
		),
		filterDecisions: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mcp_filter_decisions_total",
				Help: "Content-filter decisions by route, backend, scope, and action.",
			},
			[]string{"route", "backend", "scope", "action"},
		),
		filterStatus: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mcp_filter_status_total",
				Help: "X-Content-Filter-Status header values emitted to downstream.",
			},
			[]string{"route", "backend", "status"},
		),
		filterInflight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mcp_filter_inflight",
				Help: "In-flight content-filter dispatch calls per route/backend.",
			},
			[]string{"route", "backend"},
		),
		filterQueueDepth: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "mcp_filter_queue_depth",
				Help: "Depth of the admission queue per pipeline stage.",
			},
			[]string{"stage"},
		),
		workerPanics: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "mcp_filter_worker_panics_total",
				Help: "Count of panics caught by safeGo in content-filter worker goroutines.",
			},
			[]string{"worker"},
		),
	}

	reg.MustRegister(
		m.piiCalls,
		m.piiCallDuration,
		m.piiChunks,
		m.piiBytes,
		m.cacheLookups,
		m.jiraCalls,
		m.jiraCallDuration,
		m.circuitState,
		m.circuitTransitions,
		m.filterDecisions,
		m.filterStatus,
		m.filterInflight,
		m.filterQueueDepth,
		m.workerPanics,
	)

	return m
}

// WithCardinalityLimit installs a [CardinalityGuard] on the high-
// cardinality filter metrics (decisions, status, inflight). The cap
// is the maximum number of unique label tuples per metric. Once
// reached, new tuples are rewritten to [CardinalityOverflowLabel]
// so the metric vector cannot exceed the cap + 1 series.
//
// Returns the receiver so callers can chain:
//
//	m := NewPrometheusMetrics(reg).WithCardinalityLimit(1024)
//
// Pass 0 to disable (default). A single shared guard would be wrong
// because decisions, status, and inflight have different label
// tuple shapes; each gets its own guard.
func (m *PrometheusMetrics) WithCardinalityLimit(capacity int) *PrometheusMetrics {
	if capacity <= 0 {
		m.decisionGuard = nil
		m.statusGuard = nil
		m.inflightGuard = nil
		return m
	}
	m.decisionGuard = NewCardinalityGuard(capacity, nil)
	m.statusGuard = NewCardinalityGuard(capacity, nil)
	m.inflightGuard = NewCardinalityGuard(capacity, nil)
	return m
}

// DecisionGuard returns the decisions-cardinality guard. nil means no
// cap is enforced. Exposed so tests and dashboards can read the
// [CardinalityGuard.OverflowCount] directly.
func (m *PrometheusMetrics) DecisionGuard() *CardinalityGuard { return m.decisionGuard }

// StatusGuard returns the status-cardinality guard. nil means no cap.
func (m *PrometheusMetrics) StatusGuard() *CardinalityGuard { return m.statusGuard }

// InflightGuard returns the inflight-cardinality guard. nil means no
// cap.
func (m *PrometheusMetrics) InflightGuard() *CardinalityGuard { return m.inflightGuard }

// AsPII returns an adapter that implements [PIIMetrics]. Safe for
// concurrent use.
func (m *PrometheusMetrics) AsPII() PIIMetrics { return promPIIAdapter{m: m} }

// AsJira returns an adapter that implements [JiraMetrics]. Safe for
// concurrent use.
func (m *PrometheusMetrics) AsJira() JiraMetrics { return promJiraAdapter{m: m} }

// AsBreaker returns an adapter that implements [BreakerObserver]. Safe
// for concurrent use.
func (m *PrometheusMetrics) AsBreaker() BreakerObserver { return promBreakerAdapter{m: m} }

// RecordDecision increments mcp_filter_decisions_total. Intended to be
// called by the gateway wire-up layer (or a Dispatcher middleware)
// once per dispatch, with the ACTION returned to the caller (pass /
// redact / reject). The route and backend labels are low-cardinality
// by construction — a finite set of backends × a finite set of routes
// defined in the content-filter policy.
func (m *PrometheusMetrics) RecordDecision(route, backend string, scope Scope, action Action) {
	if m == nil {
		return
	}
	labels := []string{
		labelOrDash(route),
		labelOrDash(backend),
		string(scope),
		string(action),
	}
	if m.decisionGuard != nil {
		labels = m.decisionGuard.Normalize(labels...)
	}
	m.filterDecisions.WithLabelValues(labels...).Inc()
}

// RecordStatus increments mcp_filter_status_total. Called by the
// gateway layer immediately after writing the X-Content-Filter-Status
// response header (L04), so dashboards can correlate client-visible
// status values with backend policy outcomes.
func (m *PrometheusMetrics) RecordStatus(route, backend, status string) {
	if m == nil {
		return
	}
	labels := []string{
		labelOrDash(route),
		labelOrDash(backend),
		labelOrDash(status),
	}
	if m.statusGuard != nil {
		labels = m.statusGuard.Normalize(labels...)
	}
	m.filterStatus.WithLabelValues(labels...).Inc()
}

// IncInflight raises the mcp_filter_inflight gauge for (route,
// backend). Pair with [PrometheusMetrics.DecInflight] via defer so
// panics (recovered upstream by safeGo) never leak gauge counts.
func (m *PrometheusMetrics) IncInflight(route, backend string) {
	if m == nil {
		return
	}
	labels := []string{labelOrDash(route), labelOrDash(backend)}
	if m.inflightGuard != nil {
		labels = m.inflightGuard.Normalize(labels...)
	}
	m.filterInflight.WithLabelValues(labels...).Inc()
}

// DecInflight lowers the mcp_filter_inflight gauge for (route,
// backend).
func (m *PrometheusMetrics) DecInflight(route, backend string) {
	if m == nil {
		return
	}
	labels := []string{labelOrDash(route), labelOrDash(backend)}
	if m.inflightGuard != nil {
		labels = m.inflightGuard.Normalize(labels...)
	}
	m.filterInflight.WithLabelValues(labels...).Dec()
}

// SetQueueDepth sets mcp_filter_queue_depth for the given pipeline
// stage. Used by the admission semaphore (L02) and the audit log
// channel writer (L13) to publish back-pressure.
func (m *PrometheusMetrics) SetQueueDepth(stage string, depth int) {
	if m == nil {
		return
	}
	m.filterQueueDepth.WithLabelValues(labelOrDash(stage)).Set(float64(depth))
}

// RecordPanic increments mcp_filter_worker_panics_total for the named
// worker. Called from [safeGo] whenever a goroutine panic is caught.
// The counter going non-zero should page operators: a panic in the
// hot path is a serious bug.
func (m *PrometheusMetrics) RecordPanic(worker string) {
	if m == nil {
		return
	}
	m.workerPanics.WithLabelValues(labelOrDash(worker)).Inc()
}

// promPIIAdapter implements [PIIMetrics] on top of [PrometheusMetrics].
type promPIIAdapter struct{ m *PrometheusMetrics }

func (a promPIIAdapter) RecordCall(outcome, piiContext string) {
	a.m.piiCalls.WithLabelValues(labelOrDash(outcome), labelOrDash(piiContext)).Inc()
}

func (a promPIIAdapter) ObserveCallDuration(d time.Duration, piiContext string) {
	a.m.piiCallDuration.WithLabelValues(labelOrDash(piiContext)).Observe(d.Seconds())
}

func (a promPIIAdapter) ObserveChunkFanout(chunks int, piiContext string) {
	a.m.piiChunks.WithLabelValues(labelOrDash(piiContext)).Observe(float64(chunks))
}

func (a promPIIAdapter) AddBytes(n int64, piiContext string) {
	a.m.piiBytes.WithLabelValues(labelOrDash(piiContext)).Add(float64(n))
}

func (a promPIIAdapter) RecordCacheLookup(cache, outcome string) {
	a.m.cacheLookups.WithLabelValues(labelOrDash(cache), labelOrDash(outcome)).Inc()
}

// promJiraAdapter implements [JiraMetrics] on top of [PrometheusMetrics].
type promJiraAdapter struct{ m *PrometheusMetrics }

func (a promJiraAdapter) RecordCall(outcome, op string) {
	a.m.jiraCalls.WithLabelValues(labelOrDash(outcome), labelOrDash(op)).Inc()
}

func (a promJiraAdapter) ObserveCallDuration(d time.Duration, op string) {
	a.m.jiraCallDuration.WithLabelValues(labelOrDash(op)).Observe(d.Seconds())
}

// AsAdmission returns an adapter that implements [PIIAdmissionMetrics].
// Safe for concurrent use. Intended wiring from bootstrap:
//
//	m := NewPrometheusMetrics(registry)
//	SetAdmissionMetrics(m.AsAdmission())
func (m *PrometheusMetrics) AsAdmission() PIIAdmissionMetrics {
	return promAdmissionAdapter{m: m}
}

// promAdmissionAdapter implements [PIIAdmissionMetrics] on top of
// [PrometheusMetrics]. Inflight is published as the existing
// mcp_filter_inflight gauge under the synthetic `route=_global_,
// backend=pii_admission` labels so operators can alert on the
// process-wide saturation without adding a new metric vector. Shed
// events count into mcp_filter_decisions_total with
// `scope=_admission_, action=shed` for the same reason.
type promAdmissionAdapter struct{ m *PrometheusMetrics }

func (a promAdmissionAdapter) SetInflight(n int) {
	if a.m == nil {
		return
	}
	a.m.filterInflight.WithLabelValues("_global_", "pii_admission").Set(float64(n))
}

func (a promAdmissionAdapter) SetQueueDepth(n int) {
	if a.m == nil {
		return
	}
	a.m.filterQueueDepth.WithLabelValues("pii_admission").Set(float64(n))
}

func (a promAdmissionAdapter) RecordShed() {
	if a.m == nil {
		return
	}
	a.m.filterDecisions.WithLabelValues("_global_", "pii_admission", "_admission_", "shed").Inc()
}

// promBreakerAdapter implements [BreakerObserver] on top of
// [PrometheusMetrics].
type promBreakerAdapter struct{ m *PrometheusMetrics }

func (a promBreakerAdapter) OnState(name string, state CircuitState) {
	a.m.circuitState.WithLabelValues(labelOrDash(name)).Set(float64(state))
}

func (a promBreakerAdapter) OnTransition(name string, from, to CircuitState) {
	a.m.circuitTransitions.WithLabelValues(
		labelOrDash(name),
		from.String(),
		to.String(),
	).Inc()
}
