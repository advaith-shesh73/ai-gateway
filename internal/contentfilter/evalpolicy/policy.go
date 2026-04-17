// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter/wire"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// EvalPolicy is the Policy implementation ported from PR 95. Its
// zero value is NOT usable — construct with [New].
//
// Goroutine-safety: the struct is immutable after construction. The
// embedded llmClient is expected to be concurrency-safe (the
// production implementation is; tests swap in fakes that also are).
type EvalPolicy struct {
	cfg       Config
	client    llmClient
	filterSet map[string]struct{}
	log       *slog.Logger
}

// PolicyName is the stable identifier exposed to
// [contentfilter.ServerConfig] via its "policy" field. Kept as an
// exported constant so tests and downstream wiring can reference it
// without string duplication.
const PolicyName = "eval"

// New constructs an EvalPolicy. It applies defaults, validates, and
// builds the LLM client. Returns a descriptive error when the config
// is rejected — operators see this at service startup, not at first
// request. Takes Config by value so callers can pass a literal; the
// internal copy kept on the struct is the validated/defaulted one.
// Called exactly once per process at startup so the value-copy cost
// is irrelevant.
//
//nolint:gocritic // hugeParam: deliberate value receiver for ergonomic startup API.
func New(cfg Config) (*EvalPolicy, error) {
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("eval policy config: %w", err)
	}
	return &EvalPolicy{
		cfg:       cfg,
		client:    newHTTPLLMClient(&cfg),
		filterSet: cfg.toolFilterSet(),
		log:       slog.Default(),
	}, nil
}

// newWithClient is a test-only constructor that takes a pre-built
// llmClient. Kept unexported so the production seam stays narrow;
// tests in evalpolicy_test.go access it via the test helper file.
//
//nolint:gocritic // hugeParam: mirrors New's signature for consistency.
func newWithClient(cfg Config, client llmClient) *EvalPolicy {
	cfg.ApplyDefaults()
	return &EvalPolicy{
		cfg:       cfg,
		client:    client,
		filterSet: cfg.toolFilterSet(),
		log:       slog.Default(),
	}
}

// Name returns the stable identifier.
func (p *EvalPolicy) Name() string { return PolicyName }

// Filter implements [contentfilter.Policy]. The method encodes five
// behaviours that mirror PR 95:
//
//  1. Request-scope invocations always ActionPass (PR 95 was
//     postToolUse-only).
//  2. Tools outside [Config.FilteredTools] always ActionPass.
//  3. Non-JSON-RPC-response bodies always ActionPass (defensive;
//     gateway SHOULD only call us on responses).
//  4. Successful LLM calls: the pipeline result replaces the
//     response.result JSON and is returned as ActionRedact.
//  5. LLM failure: the entire tool_output is replaced with
//     [filterUnavailableText] (wrapped in the same MCP shape as the
//     original) and returned as ActionRedact. This is PR 95's safe-
//     redaction fallback — the filter NEVER fails open.
//
// The method never returns an error for policy-level failures; those
// are surfaced as ActionRedact (safe-redaction). An error return
// is reserved for gateway envelope problems (malformed base64, non-
// JSON-RPC body) the server layer MUST treat as a 500 so the
// gateway's FailurePolicy applies.
func (p *EvalPolicy) Filter(ctx context.Context, req *wire.FilterRequest) (*wire.FilterResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("filter request is nil")
	}

	if wire.Scope(req.Scope) != wire.ScopeResponse {
		return &wire.FilterResponse{Action: string(wire.ActionPass)}, nil
	}

	if _, ok := p.filterSet[req.Tool]; !ok {
		return &wire.FilterResponse{Action: string(wire.ActionPass)}, nil
	}

	body, err := base64.StdEncoding.DecodeString(req.BodyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode bodyBase64: %w", err)
	}

	var rpc jsonRPCResponse
	if uerr := json.Unmarshal(body, &rpc); uerr != nil {
		// Not a JSON-RPC envelope — pass through. The gateway
		// should not be calling us on such bodies but we
		// refuse to corrupt them if it does.
		p.log.WarnContext(ctx, "eval policy: body is not JSON-RPC, passing through",
			"tool", req.Tool, "err", uerr.Error())
		return &wire.FilterResponse{Action: string(wire.ActionPass)}, nil
	}
	if len(rpc.Result) == 0 {
		return &wire.FilterResponse{Action: string(wire.ActionPass)}, nil
	}

	ticketID := p.resolveTicketID(req.Headers)

	filtered, pipelineErr := filterToolOutput(ctx, p.client, req.Tool, ticketID, string(rpc.Result))
	if pipelineErr != nil {
		p.log.WarnContext(ctx, "eval policy: LLM call failed, applying safe redaction",
			"tool", req.Tool, "err", pipelineErr.Error())
		filtered = p.safeRedaction(rpc.Result)
	}

	newBody, err := rebuildJSONRPCResponse(&rpc, []byte(filtered))
	if err != nil {
		// The LLM returned a replacement that does not parse as
		// JSON (only possible on the non-MCP-wrapped path). Do
		// NOT leak the original body — fall back to safe
		// redaction and retry the rebuild. The fallback always
		// produces valid JSON (object wrapping the sentinel).
		p.log.WarnContext(ctx, "eval policy: LLM returned non-JSON replacement, applying safe redaction",
			"tool", req.Tool, "err", err.Error())
		filtered = p.safeRedaction(rpc.Result)
		newBody, err = rebuildJSONRPCResponse(&rpc, []byte(filtered))
		if err != nil {
			return nil, fmt.Errorf("rebuild JSON-RPC response: %w", err)
		}
		pipelineErr = fmt.Errorf("LLM produced non-JSON output")
	}
	return &wire.FilterResponse{
		Action:     string(wire.ActionRedact),
		BodyBase64: base64.StdEncoding.EncodeToString(newBody),
		Reason:     p.redactReason(pipelineErr),
	}, nil
}

// redactReason returns a short operator-facing string describing why
// we redacted. Distinguishing "LLM succeeded" from "safe redaction"
// matters in the audit log; beyond that we do NOT include the LLM
// error detail in the reason string (it flows to logs via WarnContext
// and can be high-cardinality).
func (p *EvalPolicy) redactReason(err error) string {
	if err != nil {
		return "eval: LLM unavailable, safe redaction applied"
	}
	return "eval: LLM-filtered resolution content"
}

// resolveTicketID returns the ticket id to stamp into the prompt.
// Forwarded header wins over Config.EvalTicketID so one pod can serve
// multiple concurrent evaluations. Header lookup is
// case-insensitive because net/http canonicalises headers.
func (p *EvalPolicy) resolveTicketID(headers map[string][]string) string {
	if p.cfg.TicketHeader != "" && len(headers) > 0 {
		key := http.CanonicalHeaderKey(p.cfg.TicketHeader)
		if vs, ok := headers[key]; ok && len(vs) > 0 && vs[0] != "" {
			return vs[0]
		}
	}
	return p.cfg.EvalTicketID
}

// safeRedaction builds the fallback body when the LLM call fails
// or returns unparseable content. Guarantees that the output is
// valid JSON (so rebuildJSONRPCResponse can substitute it into
// rpc.Result without corrupting the envelope).
//
// Two cases:
//
//   - resultJSON is an MCP wrapper → replace the first text item
//     with the unavailable sentinel and return the re-serialised
//     wrapper. An agent inspecting content[0].text still sees a
//     valid string, just the sentinel instead of leak-prone data.
//   - resultJSON is not an MCP wrapper → emit an opaque object
//     {"error": "<sentinel>"} so the client gets a shape-
//     compatible response. We NEVER reflect any field from the
//     original result, so no leak is possible.
func (p *EvalPolicy) safeRedaction(resultJSON json.RawMessage) string {
	_, wrapper := parseMCPOutput(string(resultJSON))
	if wrapper != nil {
		rebuilt, err := rebuildMCPOutput(filterUnavailableText, wrapper)
		if err == nil {
			return rebuilt
		}
		p.log.Warn("eval policy: safe-redaction rebuild failed, emitting opaque fallback",
			"err", err.Error())
	}
	// Fallback path: opaque JSON object. Hand-construct via
	// json.Marshal so the output is always valid.
	obj, err := json.Marshal(map[string]string{"error": filterUnavailableText})
	if err != nil {
		// Cannot happen for a map[string]string, but be
		// conservative: emit a literal JSON object so the
		// substitution in rebuildJSONRPCResponse can still
		// succeed.
		return `{"error":"` + filterUnavailableText + `"}`
	}
	return string(obj)
}

// jsonRPCResponse is the subset of the JSON-RPC 2.0 envelope the
// policy touches. Result is carried as RawMessage so we can replace
// it byte-for-byte without re-encoding its fields; ID and Jsonrpc
// pass through.
//
// The gateway restores the ID after we return (see
// applyContentFilterOnResponseWithStatus), but we still preserve it
// here so the server's log of the outbound body matches what the
// client eventually sees.
type jsonRPCResponse struct {
	Jsonrpc string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// rebuildJSONRPCResponse substitutes newResult into rpc and returns
// the fully-encoded bytes. newResult MUST be valid JSON (the pipeline
// guarantees this because rebuildMCPOutput emits from json.Marshal).
// Returns an error if the new result is not decodable — a defensive
// check that guards against tests accidentally feeding raw text.
// Takes rpc by pointer to avoid copying the RawMessage slices on a
// hot path.
func rebuildJSONRPCResponse(rpc *jsonRPCResponse, newResult []byte) ([]byte, error) {
	// Validate that newResult is JSON-parseable so we don't
	// encode a broken body into the gateway's response stream.
	var probe any
	if err := json.Unmarshal(newResult, &probe); err != nil {
		return nil, fmt.Errorf("replacement result is not valid JSON: %w", err)
	}
	out := struct {
		Jsonrpc string          `json:"jsonrpc,omitempty"`
		ID      json.RawMessage `json:"id,omitempty"`
		Result  json.RawMessage `json:"result"`
	}{
		Jsonrpc: rpc.Jsonrpc,
		ID:      rpc.ID,
		Result:  newResult,
	}
	if out.Jsonrpc == "" {
		out.Jsonrpc = "2.0"
	}
	return json.Marshal(out)
}
