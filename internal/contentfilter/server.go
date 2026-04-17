// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package contentfilter

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter/wire"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// maxFilterRequestBytes bounds the size of the JSON envelope the
// server will accept. Mirrors the 2 MiB cap the gateway enforces on
// the response side so neither end can be DOS'd by an oversized
// request.
const maxFilterRequestBytes = 2 << 20

// defaultInvocationTimeout is the per-request upper bound applied
// when the operator does not set one. Matches the gateway's default
// content-filter timeout so the two stay in lockstep by default.
const defaultInvocationTimeout = 10 * time.Second

// Server wraps a [Policy] in the HTTP surface the gateway expects.
// One Server serves at most one Policy — multi-policy deployments
// run multiple Server processes behind different DNS names, which
// keeps routing decisions cleanly in Kubernetes rather than in
// in-process dispatch code.
type Server struct {
	policy  Policy
	timeout time.Duration
	log     *slog.Logger
}

// NewServer returns a Server that routes every POST /filter call to
// policy. A nil policy is rejected at startup (the service has
// nothing to do without one). timeout caps the per-invocation
// deadline; pass 0 to use the package default.
func NewServer(policy Policy, timeout time.Duration, log *slog.Logger) (*Server, error) {
	if policy == nil {
		return nil, errors.New("content filter server requires a policy")
	}
	if timeout <= 0 {
		timeout = defaultInvocationTimeout
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{policy: policy, timeout: timeout, log: log}, nil
}

// Handler returns the http.Handler that implements the wire
// contract. Mount at whatever path the operator chose; by convention
// /filter.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /filter", s.handleFilter)
	// /healthz lets Kubernetes probe readiness without exercising
	// the LLM path. It returns 200 as long as the server is
	// accepting requests; it does NOT verify the upstream LLM
	// because a transient LLM outage is not a reason to take the
	// whole pod out of rotation during shadow rollout.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return mux
}

// handleFilter is the request handler. It decodes the envelope,
// hands off to the policy under a bounded-timeout context, and
// writes back the policy's verdict. Errors at the protocol layer
// produce 4xx/5xx; errors from the policy produce a
// ActionReject response so the gateway can fail-closed without
// inferring policy from HTTP status codes.
func (s *Server) handleFilter(w http.ResponseWriter, r *http.Request) {
	defer func() { _ = r.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxFilterRequestBytes+1))
	if err != nil {
		s.writeErr(w, http.StatusBadRequest, "read request body", err)
		return
	}
	if len(raw) > maxFilterRequestBytes {
		s.writeErr(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("filter request exceeds %d bytes", maxFilterRequestBytes), nil)
		return
	}
	var req wire.FilterRequest
	if uerr := json.Unmarshal(raw, &req); uerr != nil {
		s.writeErr(w, http.StatusBadRequest, "decode filter request", uerr)
		return
	}

	ctx, cancel := contextWithTimeout(r.Context(), s.timeout)
	defer cancel()

	resp, ferr := s.policy.Filter(ctx, &req)
	if ferr != nil {
		s.log.WarnContext(r.Context(), "policy returned error",
			"policy", s.policy.Name(),
			"tool", req.Tool,
			"backend", req.Backend,
			"err", ferr.Error(),
		)
		// Surface the failure as a 500 so the gateway can apply
		// its FailurePolicy (fail-open vs fail-closed). We
		// deliberately do NOT return a reject verdict here —
		// policy errors are an operational signal, and conflating
		// them with a real reject would pollute the decisions
		// counter.
		s.writeErr(w, http.StatusInternalServerError, "policy error", ferr)
		return
	}
	if resp == nil {
		s.writeErr(w, http.StatusInternalServerError, "policy returned nil response", nil)
		return
	}
	if !isKnownAction(wire.Action(resp.Action)) {
		s.writeErr(w, http.StatusInternalServerError,
			fmt.Sprintf("policy returned unknown action %q", resp.Action), nil)
		return
	}

	body, err := json.Marshal(resp)
	if err != nil {
		s.writeErr(w, http.StatusInternalServerError, "marshal filter response", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// isKnownAction reports whether a is one of the wire action
// constants. Used so typos in a policy implementation produce a 500
// (operator sees it immediately) rather than leaking through as an
// opaque unknown-action to the gateway.
func isKnownAction(a wire.Action) bool {
	switch a {
	case wire.ActionPass, wire.ActionRedact, wire.ActionReject:
		return true
	default:
		return false
	}
}

// writeErr logs and emits a plain-text error body. The gateway side
// does NOT parse error bodies so structure is unnecessary; the log
// line is where operators find the detail.
func (s *Server) writeErr(w http.ResponseWriter, status int, summary string, err error) {
	if err != nil {
		s.log.Warn("filter error", "summary", summary, "err", err.Error(), "status", status)
	} else {
		s.log.Warn("filter error", "summary", summary, "status", status)
	}
	http.Error(w, summary, status)
}
