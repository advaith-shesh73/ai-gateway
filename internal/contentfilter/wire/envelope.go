// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package wire defines the HTTP envelope types that the gateway's MCP
// content-filter hook uses to talk to a filter service. It is the
// public stable contract between the gateway and every filter
// implementation (Go, Python, or otherwise) — changing these types
// requires a coordinated rollout.
//
// The gateway-side producer lives in internal/mcpproxy/contentfilter.go
// under unexported names (contentFilterRequest, contentFilterResponse);
// those types and these must stay shape-compatible. Enforcement tests
// in mcpproxy decode payloads produced by this package to catch drift.
package wire

// Scope identifies the tools/call lifecycle phase the filter is
// evaluating. The gateway copies the value from the incoming request;
// filter services MAY branch behaviour on it but MUST NOT rewrite it.
type Scope string

const (
	// ScopeRequest is set when the gateway invokes the filter before
	// forwarding tools/call params to the backend.
	ScopeRequest Scope = "Request"
	// ScopeResponse is set when the gateway invokes the filter after
	// the backend returns a result, before writing it to the client.
	ScopeResponse Scope = "Response"
)

// Action is the verdict a filter service returns for a single
// invocation. Unknown values MUST be treated as a policy failure by
// the gateway and are subject to the configured FailurePolicy.
type Action string

const (
	// ActionPass leaves the body unchanged.
	ActionPass Action = "pass"
	// ActionRedact replaces the body with BodyBase64. The new body
	// MUST be a valid JSON-RPC message of the same kind (request or
	// response) as the original. The gateway restores the original
	// JSON-RPC ID so filters never need to preserve it.
	ActionRedact Action = "redact"
	// ActionReject causes the gateway to return a JSON-RPC error to
	// the client in place of the original exchange. Reason, if
	// set, is used as the error message.
	ActionReject Action = "reject"
)

// FilterRequest is the JSON envelope POSTed to a filter service by
// the gateway. All fields are always populated; Headers and Tool are
// always present (possibly empty strings / empty maps).
//
// The body is base64-encoded so the wire format is robust to
// non-UTF-8 content (binary arguments, embedded NULs, etc.).
type FilterRequest struct {
	// Route is the MCPGatewayRoute name that the request arrived
	// on. Label-safe (no PII); the gateway validates it before
	// emission.
	Route string `json:"route"`
	// Backend is the backend name selected by the route's routing
	// rules. Case-preserving; servers comparing names MUST
	// lowercase before dispatching so operators can keep
	// human-friendly casing in their CRDs.
	Backend string `json:"backend"`
	// Scope is the lifecycle phase; see [Scope].
	Scope string `json:"scope"`
	// MCPMethod is the JSON-RPC method name (usually
	// "tools/call"). Forwarded so filters can whitelist behaviour
	// without parsing the body.
	MCPMethod string `json:"mcpMethod"`
	// Tool is the MCP tool name when this is a tools/call;
	// otherwise empty. Used by filters to gate policy by tool.
	Tool string `json:"tool,omitempty"`
	// Headers is the whitelisted subset of client HTTP headers
	// propagated per the filter's forwardHeaders config. Always
	// non-nil (possibly empty). Keys are http.CanonicalHeaderKey.
	Headers map[string][]string `json:"headers"`
	// BodyBase64 is the full JSON-RPC body, base64-encoded.
	BodyBase64 string `json:"bodyBase64"`
	// ContentType is the MIME type of the decoded body. The
	// gateway always sends "application/json".
	ContentType string `json:"contentType"`
}

// FilterResponse is the JSON envelope returned by a filter service.
// At minimum Action MUST be populated; the remaining fields are used
// only by specific actions.
type FilterResponse struct {
	// Action is the filter's verdict; see [Action] for the valid
	// values. Unknown values are treated as a policy failure.
	Action string `json:"action"`
	// BodyBase64 is the replacement JSON-RPC body when Action ==
	// ActionRedact. Ignored for other actions. The JSON-RPC ID of
	// the original message is always restored by the gateway, so
	// the filter does not need to preserve it.
	BodyBase64 string `json:"bodyBase64,omitempty"`
	// Reason is a free-form string used in operational logs and,
	// for ActionReject, propagated into the JSON-RPC error
	// message returned to the client. Keep it short and
	// human-readable; do NOT include raw user content.
	Reason string `json:"reason,omitempty"`
}
