// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

// Package contentfilter hosts the standalone content-filter service
// binary (cmd/content-filter) and the pluggable Policy interface that
// filter strategies implement.
//
// The service terminates the wire contract defined in
// internal/contentfilter/wire and routes each invocation to exactly
// one registered Policy, keyed by the `policy` type in the runtime
// config. See internal/contentfilter/evalpolicy for the reference
// implementation (a verbatim Go port of the PR 95 Cursor-Hooks
// evaluation filter).
package contentfilter

import (
	"context"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter/wire"
)

// Policy is implemented by every filter strategy that can be plugged
// into the content-filter service. Implementations MUST be
// concurrent-safe (the server fans out invocations from an unbounded
// number of goroutines) and MUST NOT mutate the input envelope.
//
// The canonical implementation is [evalpolicy.EvalPolicy], which
// ports the PR 95 LLM-powered semantic redactor. Future strategies
// (regex, allowlist, quota) live alongside it under
// internal/contentfilter/<name>.
type Policy interface {
	// Filter evaluates a single request and returns the verdict.
	// Implementations MUST set Response.Action to one of the
	// wire.Action constants; the server rejects unknown values as
	// policy failures.
	//
	// On ActionRedact the implementation MUST set BodyBase64 to a
	// valid replacement JSON-RPC body of the same kind (request
	// or response) as the input. On ActionReject, Reason is
	// propagated to the client.
	//
	// The ctx carries both the server's request deadline and the
	// gateway's own timeout (whichever is shorter). Policies MUST
	// respect ctx.Done() so slow LLM calls cannot stall the
	// service under load.
	Filter(ctx context.Context, req *wire.FilterRequest) (*wire.FilterResponse, error)

	// Name returns the policy's stable identifier, matching the
	// `policy.type` key in server config. Used for logging and
	// metric labels.
	Name() string
}

// PassThroughPolicy is a trivial Policy that returns ActionPass for
// every request. It is the default when no policy is configured, and
// doubles as a smoke-test handler in integration tests.
type PassThroughPolicy struct{}

// Name returns the policy identifier.
func (PassThroughPolicy) Name() string { return "passthrough" }

// Filter always returns ActionPass.
func (PassThroughPolicy) Filter(_ context.Context, _ *wire.FilterRequest) (*wire.FilterResponse, error) {
	return &wire.FilterResponse{Action: string(wire.ActionPass)}, nil
}
