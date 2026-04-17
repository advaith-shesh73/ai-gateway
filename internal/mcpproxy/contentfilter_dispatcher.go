// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"log/slog"
	"strings"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// Dispatcher is the in-process equivalent of app/filter_core.py.
//
// Design intent
// -------------
//
// The Python dispatcher is a frozen dataclass holding an immutable
// `handlers` table plus an `asyncio`-based `dispatch` coroutine. The Go
// port drops `asyncio` (handlers are sync with context.Context) but
// keeps the same table-driven shape: one map lookup by lowercase
// backend name, fall through to DefaultHandler on miss, and route by
// Scope ("Request" vs "Response").
//
// Immutability matters because the dispatcher is shared across every
// in-flight request under a single filter config. A handler added
// mid-flight via a config reload would race with an ongoing dispatch;
// the controller layer MUST swap out the Dispatcher pointer atomically
// on reload rather than mutating an existing one.
//
// Parity notes
// ------------
//
// The Python version carries a per-dispatch structured log line after
// the handler returns. The Go port emits the same line through the
// dispatcher's slog.Logger, with the same keys so log queries work
// across eras.
type Dispatcher struct {
	// policy is the validated content-filter policy. Held by pointer so
	// callers can't mutate it mid-flight without going through the
	// controller's atomic-swap path.
	policy *filterapi.MCPContentFilterPolicy
	// pii is the anonymize client shared across all handlers; nil if
	// no PII handling is configured.
	pii *PIIClient
	// jira is the T0-reconstruction client; nil if Jira handling is
	// disabled or credentials are missing.
	jira *JiraClient
	// handlers maps lowercase backend name → handler instance. Registered
	// aliases (e.g. "atlassian" and "jira") point at the same instance.
	handlers map[string]Handler
	// defaultHandler handles any backend not in `handlers`. Never nil.
	defaultHandler Handler
	// logger is the dispatcher's structured logger; all dispatch log
	// lines and handler-derived loggers descend from this one.
	logger *slog.Logger
	// metrics, when non-nil, receives per-dispatch decision and
	// inflight observations. A nil value disables all metric
	// emission from the dispatcher layer (the PII and Jira clients
	// remain observable via their own configured observers).
	metrics *PrometheusMetrics
}

// Policy returns the dispatcher's policy. Exposed for tests and for the
// gateway wire-up layer that wants to inspect wire limits.
func (d *Dispatcher) Policy() *filterapi.MCPContentFilterPolicy { return d.policy }

// Handlers returns a read-only snapshot of the registered handler table.
// Intended for tests and debug tooling; do not mutate the map.
func (d *Dispatcher) Handlers() map[string]Handler {
	out := make(map[string]Handler, len(d.handlers))
	for k, v := range d.handlers {
		out[k] = v
	}
	return out
}

// DefaultHandlerInstance returns the fallback handler. Exposed for tests.
func (d *Dispatcher) DefaultHandlerInstance() Handler { return d.defaultHandler }

// Dispatch routes a single FilterRequest through the dispatcher.
//
// Contract:
//   - Unknown backend → falls through to the DefaultHandler.
//   - Unknown scope   → immediate reject with CodeInvalidRequest.
//   - Handler lookup is case-insensitive on backend name.
//   - The returned FilterResponse is safe to forward to the gateway
//     body-rewrite layer as-is.
//
// The dispatcher emits ONE structured log line per call so operators
// can grep for `dispatch: route=... backend=... scope=... action=...`
// and match the Python era's log shape.
func (d *Dispatcher) Dispatch(ctx context.Context, req *FilterRequest, body any) FilterResponse {
	if req == nil {
		return RejectResponse(
			"dispatcher: nil request (programmer error)",
			CodeInvalidRequest,
			msgInvalidRequest,
		)
	}
	backendLower := strings.ToLower(req.Backend)
	handler, ok := d.handlers[backendLower]
	if !ok {
		handler = d.defaultHandler
	}

	deps := HandlerContext{
		Policy: d.policy,
		PII:    d.pii,
		Jira:   d.jira,
		Logger: d.childLogger(req, handler.Name()),
	}

	// Publish inflight saturation for the duration of the handler
	// call. The Inc/Dec pair is guarded by metrics == nil checks
	// inside the helper methods, so a nil metrics pointer is free.
	d.metrics.IncInflight(req.Route, req.Backend)
	defer d.metrics.DecInflight(req.Route, req.Backend)

	var result FilterResponse
	switch req.Scope {
	case ScopeRequest:
		result = handler.HandleRequest(ctx, req, body, deps)
	case ScopeResponse:
		result = handler.HandleResponse(ctx, req, body, deps)
	default:
		// Programmer error at the gateway wire-up layer; reject with a
		// JSON-RPC -32600 so the client sees something intelligible.
		result = RejectResponse(
			"dispatcher: unknown scope "+string(req.Scope),
			CodeInvalidRequest,
			msgInvalidRequest,
		)
		d.logger.WarnContext(ctx, "dispatch: unknown scope",
			"route", req.Route,
			"backend", req.Backend,
			"scope", string(req.Scope),
			"tool", req.Tool,
		)
	}

	// Emit the per-decision metric after the handler runs so the
	// action label reflects the real verdict (not just what the
	// handler was asked to do). For unknown scopes we still record
	// a "reject" under the raw scope string so dashboards see the
	// anomaly instead of silently dropping it.
	d.metrics.RecordDecision(req.Route, req.Backend, req.Scope, result.Action)

	d.logger.InfoContext(ctx, "dispatch",
		"route", req.Route,
		"backend", req.Backend,
		"backendLower", backendLower,
		"tool", req.Tool,
		"scope", string(req.Scope),
		"handler", handler.Name(),
		"action", string(result.Action),
		"reason", result.Reason,
	)
	return result
}

// WithMetrics returns d with the given metrics observer attached. If
// m is nil, all metric emission from the dispatcher layer is
// disabled. Intended to be called once at construction time right
// after [BuildDispatcher] returns; subsequent invocations race with
// in-flight Dispatch calls and are discouraged (use an atomic
// Dispatcher pointer swap for reloads — see L25).
func (d *Dispatcher) WithMetrics(m *PrometheusMetrics) *Dispatcher {
	d.metrics = m
	return d
}

// childLogger builds a slog.Logger with per-dispatch context attached.
// Handlers receive it via HandlerContext.Logger so every per-handler
// log line carries the same correlation keys.
func (d *Dispatcher) childLogger(req *FilterRequest, handlerName string) *slog.Logger {
	if d.logger == nil {
		return slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}
	return d.logger.With(
		"route", req.Route,
		"backend", req.Backend,
		"scope", string(req.Scope),
		"tool", req.Tool,
		"handler", handlerName,
	)
}

// BuildDispatcher compiles the per-backend handler table from the
// policy's BackendPolicy. Mirrors app/filter_core.py:build_dispatcher.
//
// Registration rules (identical to the Python version):
//
//   - Each enabled handler registers ONE instance under every name
//     listed in its *BackendNames field. Aliases therefore share the
//     same instance (important for handlers that memoize state).
//   - Names are lowercased on registration; the backend-name lookup at
//     Dispatch is case-insensitive.
//   - The DefaultHandler's pii_scan_backends set is lowercased on
//     construction.
//   - EnableJira=true requires a non-nil jiraClient; the controller is
//     responsible for that invariant (policy validation catches missing
//     creds earlier).
//
// Parameters
//   - policy: already-validated MCPContentFilterPolicy (call .Validate()
//     before passing in).
//   - piiClient: anonymize client; nil disables PII fallback. When nil,
//     handlers that need PII MUST still return a reject verdict rather
//     than panicking.
//   - jiraClient: T0-reconstruction client; may be nil if Jira is
//     disabled.
//   - logger: base logger; if nil, a discard logger is used.
func BuildDispatcher(
	policy *filterapi.MCPContentFilterPolicy,
	piiClient *PIIClient,
	jiraClient *JiraClient,
	logger *slog.Logger,
) *Dispatcher {
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(discardWriter{}, nil))
	}

	handlers := make(map[string]Handler)

	if policy.Backends.EnableSupportGPT {
		sg := NewSupportGPTHandler()
		for _, name := range policy.Backends.SupportGPTBackendNames {
			handlers[strings.ToLower(name)] = sg
		}
	}
	if policy.Backends.EnableNuRAG {
		nu := NewNuRAGHandler()
		for _, name := range policy.Backends.NuRAGBackendNames {
			handlers[strings.ToLower(name)] = nu
		}
	}
	if policy.Backends.EnableGlean {
		gl := NewGleanHandler()
		for _, name := range policy.Backends.GleanBackendNames {
			handlers[strings.ToLower(name)] = gl
		}
	}
	if policy.Backends.EnableJira {
		jh := NewJiraHandler()
		for _, name := range policy.Backends.JiraBackendNames {
			handlers[strings.ToLower(name)] = jh
		}
	}

	// Default handler runs PII scan on any backend in the allowlist,
	// even when no dedicated handler is registered. The allowlist is
	// lowercased on entry so callers can stay case-preserving in CRDs.
	lowerScan := make([]string, 0, len(policy.Backends.PIIScanBackends))
	for _, b := range policy.Backends.PIIScanBackends {
		lowerScan = append(lowerScan, strings.ToLower(b))
	}
	defaultHandler := NewDefaultHandler(lowerScan)

	return &Dispatcher{
		policy:         policy,
		pii:            piiClient,
		jira:           jiraClient,
		handlers:       handlers,
		defaultHandler: defaultHandler,
		logger:         logger,
	}
}

// discardWriter drops every write. Used to silence dispatcher logs when
// the caller provided no logger.
type discardWriter struct{}

// Write returns len(p), nil for every call; never returns an error so
// nothing upstream sees a fake logger failure.
func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
