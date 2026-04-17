// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"fmt"
	"net/http"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// In-process wire-up layer — bridges the Python-era HTTP sidecar path
// (`applyContentFilterOnRequest` / `applyContentFilterOnResponse`) to
// the in-process Dispatcher built in PR C.3.
//
// Why keep the sidecar path at all?
// --------------------------------
// The existing apply* functions expect a `*http.Client` and a filter
// URL; both become no-ops when `cf.dispatcher` is set. Keeping the
// sidecar path alive lets operators run in "parallel" mode during
// rollout (A/B test the in-process filter against the sidecar before
// retiring the Python service) — a safety valve the handoff explicitly
// calls for in §7.7.
//
// Contract
// --------
// The dispatcher expects:
//   - body as `any` (the JSON-unmarshaled map/slice tree).
//   - headers as a `HeaderView` (already lowercased + multi-value aware).
//   - `FilterRequest` fields Route / Backend / Scope / MCPMethod / Tool.
//
// This file provides one small adapter, `dispatchInProcess`, that the
// HTTP-sidecar entry points consult first.  On the hot path the adapter
// owns exactly ONE place that converts between the gateway's on-wire
// shape (bytes) and the dispatcher's typed shape (`any`), so no
// conversion logic drifts out of sync between request and response scopes.
//
// Return tuple: (newBody, rejected, reason, err). Callers translate
// this into the final `*jsonrpc.Request` / `*jsonrpc.Response` exactly
// like the HTTP path does, so downstream code stays unchanged.

// dispatchInProcess runs a scope-specified dispatch through the
// in-process Dispatcher.
//
// Parameters match the HTTP-sidecar invoke() so the two paths are
// drop-in substitutable at the call site.
//
// Returns:
//   - newBody: bytes to forward (body on pass; rewritten body on redact).
//   - rejected: true when the handler emitted Action=reject.
//   - reason: stable reason string from the handler (for logs/errors).
//   - err: infrastructure error (decode failure, programmer error).
//     Callers apply the fail-closed policy to this error; a handler
//     returning ActionReject is NOT a dispatcher error.
func dispatchInProcess(
	ctx context.Context,
	d *Dispatcher,
	scope Scope,
	routeName filterapi.MCPRouteName,
	backendName filterapi.MCPBackendName,
	mcpMethod, tool string,
	headers http.Header,
	body []byte,
) (newBody []byte, rejected bool, reason string, err error) {
	if d == nil {
		// Programmer error: caller MUST check for a nil dispatcher
		// before invoking this path. Fail loud rather than silently
		// passing through — a mis-wired gateway must surface in tests.
		return nil, false, "",
			fmt.Errorf("dispatchInProcess: dispatcher is nil (programmer error)")
	}

	var parsed any
	if len(body) > 0 {
		if uErr := json.Unmarshal(body, &parsed); uErr != nil {
			// A non-JSON body on either scope is a protocol violation
			// in the in-process era: the gateway only ever forwards
			// JSON-RPC. Surface it like the HTTP adapter would (the
			// caller's fail-closed/fail-open policy decides action).
			return nil, false, "", fmt.Errorf("dispatchInProcess: decode body: %w", uErr)
		}
	}

	req := FilterRequest{
		Route:     routeName,
		Backend:   backendName,
		Scope:     scope,
		MCPMethod: mcpMethod,
		Tool:      tool,
		Headers:   NewHeaderView(headers),
	}

	resp := d.Dispatch(ctx, &req, parsed)

	switch resp.Action {
	case ActionPass:
		return body, false, resp.Reason, nil
	case ActionRedact:
		if len(resp.Body) == 0 {
			// An empty redact degrades to pass — matches Python and
			// matches the HTTP sidecar contract (empty body = no-op).
			return body, false, resp.Reason, nil
		}
		return resp.Body, false, resp.Reason, nil
	case ActionReject:
		// Reject is a handler verdict, NOT a dispatcher error. The
		// caller translates reason into a JSON-RPC error response.
		return nil, true, resp.Reason, nil
	default:
		// Unknown action = programmer error inside a handler. It must
		// never escape a well-implemented handler. We return a hard
		// error and let the caller's fail-closed policy decide; this
		// is strictly safer than silently passing the body through.
		return nil, false, "",
			fmt.Errorf("dispatchInProcess: handler returned unknown action %q", resp.Action)
	}
}
