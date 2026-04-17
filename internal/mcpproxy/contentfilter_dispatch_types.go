// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Types and constants the in-process content-filter dispatcher hands
// between the gateway, the dispatcher, and the per-backend handlers.
//
// Parity references:
//   - app/wire.py          → FilterRequest / FilterResponse
//   - app/backends/base.py → Handler / HandlerContext
//   - app/filter_core.py   → Dispatcher
//
// Design notes
// -----------
//
// The Python version carries a JSON envelope over HTTP; the Go port runs
// in-process so there is no envelope on the wire. We still keep the Python
// field shapes on the types so that a parity audit can map one-to-one.
// This makes debugging easier for operators who are used to reading the
// Python logs (scope=Request, backend=supportgpt, ...).
//
// A FilterRequest is immutable once constructed. Handlers MUST NOT mutate
// it; if they need a derived value (e.g. a lowercased backend name), they
// compute it locally. This is the single rule that lets us skip defensive
// copies at dispatch time.

import (
	"context"
	"log/slog"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
)

// Scope identifies whether the dispatcher is running before the backend
// sees a request (Scope="Request") or after it sends a response back to
// the client (Scope="Response"). Matches the Python literal ScopeLiteral.
//
// Using a string type (not an int enum) because the value shows up in log
// lines and metric labels — a grep for `scope=Request` on gateway logs
// should match both the Python and Go eras seamlessly.
type Scope string

// The two scopes supported. Any other value is a programmer error and
// translates to a -32600 reject at dispatch time.
const (
	ScopeRequest  Scope = "Request"
	ScopeResponse Scope = "Response"
)

// Action is the dispatcher's verdict on a single scope invocation:
//   - ActionPass:   forward the original body unchanged.
//   - ActionRedact: forward Body (the replacement bytes) and preserve the
//     original JSON-RPC `id`. Empty Body is allowed (no-op
//     redact); handlers should prefer ActionPass in that
//     case to avoid re-serializing the body unnecessarily.
//   - ActionReject: return a JSON-RPC error to the client.
type Action string

// Supported actions. Matches Python ActionLiteral.
const (
	ActionPass   Action = "pass"
	ActionRedact Action = "redact"
	ActionReject Action = "reject"
)

// Reserved JSON-RPC error codes for reject verdicts.
// Parity: app/wire.py:FilterResponse defaults.
const (
	// CodePolicyReject is the default code when a reject does not carry
	// a more specific classification.
	CodePolicyReject = -32099
	// CodePIIUnavailable is raised when PII redaction was required but
	// the PII service was unavailable (matches HANDOFF §4.2).
	CodePIIUnavailable = -32010
	// CodeJiraUnavailable is raised when Jira T0 reconstruction was
	// requested but the Jira service was unavailable.
	CodeJiraUnavailable = -32011
	// CodeInvalidRequest is raised when the envelope itself violates a
	// protocol invariant — e.g. unknown scope, multi-valued eval header
	// in strict mode. In-process, this is an invariant failure: the
	// caller-side gateway should not emit such a request.
	CodeInvalidRequest = -32600
)

// Default user-facing reject messages. Kept in constants so the reconciler
// and tests can assert on them.
const (
	msgContentPolicyViolation = "content policy violation"
	msgPIIRedactionRequired   = "pii redaction required but unavailable"
	msgJiraUnavailable        = "jira T0 reconstruction unavailable"
	msgInvalidRequest         = "invalid request"
)

// FilterRequest is the in-process equivalent of the Python
// `FilterRequest` Pydantic model. It is the parsed view of a single
// dispatcher invocation; handlers read it to decide what to do.
//
// Fields are public for handler access (Go lacks Python's __dict__ dunder).
// Keep them value types so a FilterRequest is cheap to pass and safe to
// share across goroutines.
type FilterRequest struct {
	// Route is the MCPRoute name on the CRD side. Label-safe (no PII).
	Route string
	// Backend is the backend name assigned by the route's routing rules.
	// Case-preserving; the dispatcher lowercases it internally for handler
	// lookup so operators can keep human-friendly casing in their CRDs.
	Backend string
	// Scope is "Request" or "Response". Other values reject with -32600.
	Scope Scope
	// MCPMethod is the JSON-RPC method (e.g. "tools/call"). Propagated
	// from the gateway's already-parsed request.
	MCPMethod string
	// Tool is the `params.name` for a `tools/call`, or empty otherwise.
	// Handlers use this for per-tool rules (e.g. SupportGPT's
	// EXCLUDE_SEARCH_TOOLS whitelist).
	Tool string
	// Headers is a prepared HeaderView. Callers MUST build this via
	// NewHeaderView(raw) so multi-valued tracking is correct.
	Headers HeaderView
}

// EvalTicketID is a tiny wrapper over HeaderView.EvalTicketID that
// shortens the call sites. Handlers typically only care about the ticket
// string and handle the MultiValueEvalHeaderError at the dispatcher seam.
func (r *FilterRequest) EvalTicketID(evalHeader string, strict bool) (string, error) {
	return r.Headers.EvalTicketID(evalHeader, strict)
}

// FilterResponse is the verdict a handler returns. Construct via
// PassResponse / RedactResponse / RejectResponse so the code/message
// invariants stay consistent.
//
// Parity: mirrors app/wire.py:FilterResponse.
type FilterResponse struct {
	// Action is the verdict.
	Action Action
	// Body is the replacement bytes for a redact action; unused for pass
	// and reject. May be empty for "no-op redact" — handlers should
	// prefer PassResponse in that case.
	Body []byte
	// Reason is a short human-readable string for logs; never exposed
	// to the caller. Keep PII out of this string.
	Reason string
	// Code is the JSON-RPC error code for a reject action. Ignored for
	// pass/redact. Defaults to CodePolicyReject when zero.
	Code int
	// Message is the JSON-RPC error message for a reject action.
	// Ignored for pass/redact. Defaults to msgContentPolicyViolation
	// when empty.
	Message string
}

// PassResponse returns a pass-through verdict with the given reason.
// Use this when the handler determined no mutation or rejection is
// warranted; it's the cheapest verdict (no body rebuild).
func PassResponse(reason string) FilterResponse {
	return FilterResponse{Action: ActionPass, Reason: reason}
}

// RedactResponse returns a redact verdict with the given body bytes.
// Empty body is legal but the handler should prefer PassResponse in
// that case to skip the body-replace path upstream.
func RedactResponse(body []byte, reason string) FilterResponse {
	return FilterResponse{
		Action: ActionRedact,
		Body:   body,
		Reason: reason,
	}
}

// RejectResponse returns a reject verdict using the configured code /
// message, falling back to CodePolicyReject / msgContentPolicyViolation
// when the caller leaves them zero/empty.
func RejectResponse(reason string, code int, message string) FilterResponse {
	if code == 0 {
		code = CodePolicyReject
	}
	if message == "" {
		message = msgContentPolicyViolation
	}
	return FilterResponse{
		Action:  ActionReject,
		Reason:  reason,
		Code:    code,
		Message: message,
	}
}

// HandlerContext carries the runtime dependencies shared across every
// handler invocation in one dispatch. Keeping this off-struct from the
// handler lets us add a new dependency (say, a metrics observer) without
// touching every handler signature.
//
// Parity: mirrors app/backends/base.py:HandlerContext. The Python
// context holds an AppConfig instance; here we pass the already-loaded
// MCPContentFilterPolicy so handlers don't care where it came from.
type HandlerContext struct {
	// Policy is the loaded + validated content-filter policy. Read-only
	// by handlers — the dispatcher guarantees no one mutates it in-flight.
	Policy *filterapi.MCPContentFilterPolicy
	// PII is the anonymize client. nil means PII fallback is disabled
	// at this dispatch (e.g. because EnableDefaultPII is false).
	PII *PIIClient
	// Jira is the T0-reconstruction client. nil means the Jira handler
	// is not active (EnableJira=false or creds missing); handlers that
	// need it MUST fail softly (pass_through or reject with
	// CodeJiraUnavailable, never panic on a nil pointer).
	Jira *JiraClient
	// Logger is a structured logger derived from the dispatcher's
	// logger, with dispatcher-level fields already attached (route,
	// backend, scope). Never nil.
	Logger *slog.Logger
}

// Handler is the contract every per-backend handler implements.
//
// Parity: mirrors app/backends/base.py:Handler. The two methods are
// async in Python because the PII client makes HTTP calls; in Go they
// are sync with an explicit context.Context so cancellation propagates
// through the same idioms as the rest of the gateway codebase.
//
// A Handler is stateless and safe for concurrent invocation: the
// dispatcher holds ONE instance per backend name and dispatches every
// in-flight request through it without cloning.
type Handler interface {
	// Name returns a short friendly name for logs and metrics.
	Name() string
	// HandleRequest inspects a Request-scope body and returns a verdict.
	HandleRequest(ctx context.Context, req *FilterRequest, body any, deps HandlerContext) FilterResponse
	// HandleResponse inspects a Response-scope body and returns a verdict.
	HandleResponse(ctx context.Context, req *FilterRequest, body any, deps HandlerContext) FilterResponse
}

// passThroughHandler is the all-pass default handler behavior shared by
// BaseHandler and by the dispatcher's "unknown scope" path. Exposed via
// PassThroughResponse for handlers that want to call super().
func passThroughResponse(name, reason string) FilterResponse {
	if reason == "" {
		reason = name + ": no rule matched"
	}
	return PassResponse(reason)
}

// BaseHandler is a zero-value handler that passes every scope through.
// Concrete handlers embed this and override only the scopes they care
// about. Mirrors app/backends/base.py:Handler defaults.
type BaseHandler struct {
	// HandlerName is returned from Name(); override by setting it in
	// the embedding type's constructor.
	HandlerName string
}

// Name returns the handler's display name.
func (h *BaseHandler) Name() string {
	if h.HandlerName == "" {
		return "base"
	}
	return h.HandlerName
}

// HandleRequest returns a pass verdict. Override in subclasses.
func (h *BaseHandler) HandleRequest(_ context.Context, _ *FilterRequest, _ any, _ HandlerContext) FilterResponse {
	return passThroughResponse(h.Name(), h.Name()+": no request-scope rule")
}

// HandleResponse returns a pass verdict. Override in subclasses.
func (h *BaseHandler) HandleResponse(_ context.Context, _ *FilterRequest, _ any, _ HandlerContext) FilterResponse {
	return passThroughResponse(h.Name(), h.Name()+": no response-scope rule")
}
