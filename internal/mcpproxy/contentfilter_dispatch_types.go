// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Scope is the canonical label value for "which scope did the filter
// run at" — Request (before upstream) or Response (after upstream).
// The string form is the public label on mcp_filter_decisions_total so
// changing these values breaks dashboards.
type Scope string

const (
	// ScopeRequest marks a decision produced by a Request-scope
	// filter invocation.
	ScopeRequest Scope = "Request"
	// ScopeResponse marks a decision produced by a Response-scope
	// filter invocation.
	ScopeResponse Scope = "Response"
)

// Action is the canonical label value for "what verdict did the filter
// produce". Used on mcp_filter_decisions_total; the status counter has
// its own richer enum in [FilterStatus].
type Action string

const (
	// ActionPass is the filter returning pass / forward the body
	// unchanged.
	ActionPass Action = "pass"
	// ActionRedact is the filter rewriting the body.
	ActionRedact Action = "redact"
	// ActionReject is the filter blocking the call.
	ActionReject Action = "reject"
)
