// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics is the gateway-side observer for MCP content-filter
// decisions. It registers three metric vectors with the supplied
// [prometheus.Registerer]:
//
//  1. mcp_filter_decisions_total{route,backend,scope,action}
//  2. mcp_filter_status_total{route,backend,status}
//  3. mcp_filter_inflight{route,backend}
//
// These are the only metrics the gateway emits about the content
// filter. Everything PII-, Jira-, cache-, or breaker-related now lives
// inside the external filter service (see
// panacea-agent/services/aigw-content-filter).
//
// Concurrency: all Prometheus vectors are safe for concurrent use.
// PrometheusMetrics itself owns no mutable state beyond the vectors.
//
// Registration: the constructor uses
// [prometheus.Registerer.MustRegister] internally. Registering the
// same metric twice with the same registerer panics, so callers are
// expected to build one PrometheusMetrics per process (or pass a
// fresh registry in tests).
type PrometheusMetrics struct {
	filterDecisions *prometheus.CounterVec
	filterStatus    *prometheus.CounterVec
	filterInflight  *prometheus.GaugeVec

	// Cardinality guards keep per-vector unique label tuples below
	// a cap. decisions and status are high-cardinality because
	// backend names can come from the CRD; inflight is low but
	// still capped for uniformity. Zero means no cap.
	decisionGuard *CardinalityGuard
	statusGuard   *CardinalityGuard
	inflightGuard *CardinalityGuard
}

// NewPrometheusMetrics constructs the three filter vectors and
// registers them with reg. Passing nil substitutes
// [prometheus.DefaultRegisterer]. Tests should pass a fresh
// [prometheus.NewRegistry] so parallel tests don't conflict.
func NewPrometheusMetrics(reg prometheus.Registerer) *PrometheusMetrics {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}

	m := &PrometheusMetrics{
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
	}

	reg.MustRegister(
		m.filterDecisions,
		m.filterStatus,
		m.filterInflight,
	)

	return m
}

// WithCardinalityLimit installs a [CardinalityGuard] with the given
// capacity on the three filter metrics. Capacity <= 0 clears any
// existing guards. Returns the receiver for chaining.
func (m *PrometheusMetrics) WithCardinalityLimit(capacity int) *PrometheusMetrics {
	if m == nil {
		return nil
	}
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

// RecordDecision increments mcp_filter_decisions_total. Intended to be
// called by the gateway once per filter invocation, with the action
// returned by the external filter service (pass / redact / reject or
// the shadow-mode equivalents defined in contentfilter_shadow.go).
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
// gateway immediately after writing the X-Content-Filter-Status
// response header, so dashboards can correlate client-visible status
// values with backend policy outcomes.
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
// panics never leak gauge counts.
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

// labelOrDash returns s when non-empty, or "-" otherwise. Used so
// empty label values don't collapse into a single mystery series.
func labelOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
