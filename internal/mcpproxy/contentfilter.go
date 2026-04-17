// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// contentFilterDefaultTimeout is the timeout applied to a single content
// filter invocation when no TimeoutSeconds is configured on the filter.
const contentFilterDefaultTimeout = 10 * time.Second

// contentFilterMaxBodyBytes caps the size of a filter response body that the
// gateway is willing to read. 2 MiB is large enough to cover realistic
// tools/call rewrites while providing a hard upper bound against misbehaving
// filters.
const contentFilterMaxBodyBytes = 2 << 20

// Content filter actions.
const (
	contentFilterActionPass   = "pass"
	contentFilterActionRedact = "redact"
	contentFilterActionReject = "reject"
)

// filterStatusHeader is the response header that advertises the
// content-filter outcome to downstream clients. Operators grep this
// header in debug logs; dashboards break down mcp_filter_status_total
// by the same label values.
//
// The header is stable public API — changing spelling breaks
// third-party integrations and alert rules — so it lives as a
// package constant.
const filterStatusHeader = "X-Content-Filter-Status"

// FilterStatus is the canonical value space for the
// [filterStatusHeader] response header and the status label on
// mcp_filter_status_total.
type FilterStatus string

const (
	// FilterStatusPass means the filter ran and left the body
	// unchanged.
	FilterStatusPass FilterStatus = "pass"
	// FilterStatusRedact means the filter rewrote the body.
	FilterStatusRedact FilterStatus = "redact"
	// FilterStatusReject means the filter blocked the call and the
	// gateway returned a JSON-RPC error to the client in place of
	// the upstream response.
	FilterStatusReject FilterStatus = "reject"
	// FilterStatusFailedOpen means the filter errored but the
	// route's policy was fail-open, so the body was forwarded
	// unmodified.
	FilterStatusFailedOpen FilterStatus = "failed-open"
	// FilterStatusUnavailable means the filter errored and the
	// route's policy was fail-closed, so the call was rejected as
	// if the filter had returned "reject".
	FilterStatusUnavailable FilterStatus = "unavailable"
	// FilterStatusOff means no filter was configured for the
	// current scope on this (route, backend).
	FilterStatusOff FilterStatus = "off"
	// FilterStatusDisabled means the filter is configured but the
	// kill switch is engaged — either the per-backend Enabled flag
	// is false or the process-wide GlobalDisable is set. The
	// original body is forwarded unchanged and no upstream filter
	// call is issued.
	FilterStatusDisabled FilterStatus = "disabled"
)

// filterMetrics is the optional process-wide Prometheus observer that
// [writeFilterStatus] emits status counters through. Installed once at
// bootstrap via [SetFilterMetrics]; nil means no metric emission.
var filterMetrics atomic.Pointer[PrometheusMetrics]

// SetFilterMetrics installs (or clears when nil) the package-level
// Prometheus observer used by [writeFilterStatus] and other status
// emission sites. Typically called once during gateway bootstrap
// immediately after [NewPrometheusMetrics]. Safe to call at any time;
// stores the pointer atomically.
func SetFilterMetrics(m *PrometheusMetrics) { filterMetrics.Store(m) }

// filterMetricsLoad returns the currently-installed metrics pointer,
// or nil if none has been set. Used by emission helpers.
func filterMetricsLoad() *PrometheusMetrics { return filterMetrics.Load() }

// writeFilterStatus writes the [filterStatusHeader] on w with the
// canonical status value AND emits the corresponding
// mcp_filter_status_total counter when a Prometheus observer has been
// installed via [SetFilterMetrics]. Intended to be called exactly once
// per proxied response, BEFORE w.WriteHeader — calling it after has
// no effect on the on-wire header.
//
// w may be nil on test paths that only care about the metric
// side-effect; a nil writer is tolerated.
func writeFilterStatus(w http.ResponseWriter, route filterapi.MCPRouteName, backend filterapi.MCPBackendName, status FilterStatus) {
	if w != nil {
		w.Header().Set(filterStatusHeader, string(status))
	}
	if m := filterMetricsLoad(); m != nil {
		m.RecordStatus(route, backend, string(status))
	}
}

// contentFilterScope is the runtime-internal representation of the scope at
// which the filter is being invoked.
type contentFilterScope string

const (
	contentFilterScopeRequest  contentFilterScope = "Request"
	contentFilterScopeResponse contentFilterScope = "Response"
)

// contentFilter is the runtime-compiled representation of
// [filterapi.MCPContentFilter]. It is shared between goroutines without
// mutation for the lifetime of the configuration snapshot.
//
// A contentFilter carries two mutually-exclusive invocation modes:
//
//  1. HTTP sidecar (legacy, Python era): when `dispatcher == nil`, every
//     invoke() call POSTs a JSON envelope to `url`.
//  2. In-process (Go-native): when `dispatcher != nil`, the URL field is
//     ignored and every invoke() call dispatches to the in-process
//     Dispatcher.
//
// The dual-mode design lets operators rollout the in-process filter
// behind a feature flag without rewriting CRDs first. The controller
// populates one or the other at compile time; the runtime never flips
// between modes for an in-flight request.
type contentFilter struct {
	url                     string
	invokeOnRequest         bool
	invokeOnResponse        bool
	timeout                 time.Duration
	failClosed              bool
	forwardHeadersCanonical []string
	// dispatcher, when non-nil, replaces the HTTP sidecar path with
	// in-process dispatch. Shared across all goroutines; safe for
	// concurrent use. See contentfilter_inprocess.go for the adapter.
	dispatcher *Dispatcher
	// mode is the compiled enforcement mode. Empty is treated as
	// MCPContentFilterModeEnforce at invocation time so legacy
	// configs keep their behavior.
	mode filterapi.MCPContentFilterMode
	// enabled is the compiled kill switch. nil is treated as true
	// so a config that does not carry the field stays live. See
	// [filterapi.MCPContentFilter.Enabled] for the full contract.
	enabled *bool
	// shadowSampleRatePermille is the compiled sampling budget in
	// parts per thousand (0..1000). A value of 0 is treated as 1000
	// (fully sampled) at invocation time so configs that do not
	// carry the field keep their behavior. Ignored when mode is
	// not Shadow.
	shadowSampleRatePermille int32
	// policy is an optional reference to the process-wide policy
	// snapshot. When non-nil, the gates consult GlobalDisable on
	// every invocation so a single ConfigMap edit can stop every
	// filter in the cluster. The pointer is never mutated after
	// publication; hot-reloading rebuilds the whole contentFilter.
	policy *filterapi.MCPContentFilterPolicy
}

// effectiveMode returns the filter's compiled mode, substituting
// MCPContentFilterModeEnforce for the empty string so callers do not
// have to spell the default out. Nil receivers return Enforce.
func (cf *contentFilter) effectiveMode() filterapi.MCPContentFilterMode {
	if cf == nil || cf.mode == "" {
		return filterapi.MCPContentFilterModeEnforce
	}
	return cf.mode
}

// isDisabled reports whether the kill switches are engaged. Returns
// true when GlobalDisable is set on the attached policy OR when the
// per-backend Enabled pointer is explicitly false. A nil pointer or
// a nil filter is treated as enabled (false).
func (cf *contentFilter) isDisabled() bool {
	if cf == nil {
		return false
	}
	if cf.policy != nil && cf.policy.GlobalDisable {
		return true
	}
	if cf.enabled != nil && !*cf.enabled {
		return true
	}
	return false
}

// shadowSampleRateBounded returns the effective shadow sample rate,
// clamped into the documented [0, 1000] range. Zero stored values are
// treated as 1000 so back-compat configs retain their existing
// behavior (fully sampled). Values above 1000 clamp to 1000.
func (cf *contentFilter) shadowSampleRateBounded() int32 {
	if cf == nil {
		return 1000
	}
	r := cf.shadowSampleRatePermille
	if r <= 0 {
		return 1000
	}
	if r > 1000 {
		return 1000
	}
	return r
}

// WithDispatcher returns cf with the given dispatcher attached. Returns
// the same pointer so the call is chainable with compile*:
//
//	cf, err := compileContentFilter(spec, route, backend)
//	if err != nil { ... }
//	cf = cf.WithDispatcher(d)
//
// Calling WithDispatcher(nil) unsets the dispatcher (useful in tests).
// A contentFilter is shared across goroutines so this method MUST be
// called before the filter is published to handlers; mutating a live
// filter is a race.
func (cf *contentFilter) WithDispatcher(d *Dispatcher) *contentFilter {
	if cf == nil {
		return nil
	}
	cf.dispatcher = d
	return cf
}

// compileContentFilter validates a filter configuration and returns its
// runtime form. Returns (nil, nil) when the input is nil.
func compileContentFilter(cf *filterapi.MCPContentFilter, routeName filterapi.MCPRouteName, backendName filterapi.MCPBackendName) (*contentFilter, error) {
	if cf == nil {
		return nil, nil
	}
	if cf.URL == "" {
		return nil, fmt.Errorf("content filter url is required for backend %q in route %q", backendName, routeName)
	}
	if !strings.HasPrefix(cf.URL, "http://") && !strings.HasPrefix(cf.URL, "https://") {
		return nil, fmt.Errorf("content filter url for backend %q in route %q must start with http:// or https://", backendName, routeName)
	}

	if len(cf.Scopes) == 0 {
		return nil, fmt.Errorf("content filter for backend %q in route %q must declare at least one scope", backendName, routeName)
	}

	out := &contentFilter{
		url:     cf.URL,
		timeout: contentFilterDefaultTimeout,
	}
	if cf.TimeoutSeconds > 0 {
		out.timeout = time.Duration(cf.TimeoutSeconds) * time.Second
	}

	for _, s := range cf.Scopes {
		switch s {
		case filterapi.MCPContentFilterScopeRequest:
			out.invokeOnRequest = true
		case filterapi.MCPContentFilterScopeResponse:
			out.invokeOnResponse = true
		default:
			return nil, fmt.Errorf("content filter for backend %q in route %q has unknown scope %q", backendName, routeName, s)
		}
	}

	switch cf.FailurePolicy {
	case "", filterapi.MCPContentFilterFailurePolicyPassThrough:
		out.failClosed = false
	case filterapi.MCPContentFilterFailurePolicyFail:
		out.failClosed = true
	default:
		return nil, fmt.Errorf("content filter for backend %q in route %q has unknown failure policy %q", backendName, routeName, cf.FailurePolicy)
	}

	switch cf.Mode {
	case "", filterapi.MCPContentFilterModeEnforce:
		out.mode = filterapi.MCPContentFilterModeEnforce
	case filterapi.MCPContentFilterModeShadow:
		out.mode = filterapi.MCPContentFilterModeShadow
	default:
		return nil, fmt.Errorf("content filter for backend %q in route %q has unknown mode %q", backendName, routeName, cf.Mode)
	}

	if cf.Enabled != nil {
		b := *cf.Enabled
		out.enabled = &b
	}
	if cf.ShadowSampleRatePermille < 0 || cf.ShadowSampleRatePermille > 1000 {
		return nil, fmt.Errorf("content filter for backend %q in route %q has shadowSampleRatePermille %d out of range [0,1000]", backendName, routeName, cf.ShadowSampleRatePermille)
	}
	out.shadowSampleRatePermille = cf.ShadowSampleRatePermille

	if len(cf.ForwardHeaders) > 0 {
		seen := make(map[string]struct{}, len(cf.ForwardHeaders))
		out.forwardHeadersCanonical = make([]string, 0, len(cf.ForwardHeaders))
		for _, h := range cf.ForwardHeaders {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			canon := http.CanonicalHeaderKey(h)
			if _, dup := seen[canon]; dup {
				continue
			}
			seen[canon] = struct{}{}
			out.forwardHeadersCanonical = append(out.forwardHeadersCanonical, canon)
		}
	}
	return out, nil
}

// contentFilterRequest is the JSON envelope POSTed to the filter service.
//
// Field design notes:
//   - Body is base64-encoded so that the wire format is robust to non-UTF-8
//     content (binary tool arguments, embedded null bytes, etc.).
//   - Headers is always present and may be empty.
//   - Scope/Method/Tool/Backend/Route are passed so the filter can dispatch
//     policy without parsing the body.
type contentFilterRequest struct {
	Route       string              `json:"route"`
	Backend     string              `json:"backend"`
	Scope       string              `json:"scope"`
	MCPMethod   string              `json:"mcpMethod"`
	Tool        string              `json:"tool,omitempty"`
	Headers     map[string][]string `json:"headers"`
	BodyBase64  string              `json:"bodyBase64"`
	ContentType string              `json:"contentType"`
}

// contentFilterResponse is the JSON envelope returned by the filter service.
//
//   - Action: "pass", "redact", or "reject". Unknown values are treated as
//     policy failures and subject to the FailurePolicy.
//   - BodyBase64: new JSON-RPC body to use when Action == "redact". The
//     JSON-RPC ID of the original message is always restored by the gateway,
//     so the filter does not need to preserve it.
//   - Reason: free-form string used in logs and propagated into the
//     JSON-RPC error message when Action == "reject".
type contentFilterResponse struct {
	Action     string `json:"action"`
	BodyBase64 string `json:"bodyBase64,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// errContentFilterRejected is returned by applyContentFilterOnRequest or
// applyContentFilterOnResponse when the filter explicitly rejects the call.
// Callers are expected to translate this into a JSON-RPC error.
var errContentFilterRejected = errors.New("content filter rejected request")

// errContentFilterFailed is returned when the filter could not be consulted
// and FailurePolicy is "Fail". Callers translate this into a JSON-RPC error.
var errContentFilterFailed = errors.New("content filter invocation failed")

// invokeContentFilter performs a single filter HTTP call. It returns:
//   - body: possibly rewritten JSON-RPC body, or the original body on pass.
//   - rejected: true when the filter asked to reject the call.
//   - reason:   free-form reason string (rejection or redaction), for logs.
//   - err:      non-nil only when the filter could not be consulted
//     successfully. Callers apply the FailurePolicy on err.
func (cf *contentFilter) invoke(
	ctx context.Context,
	client *http.Client,
	scope contentFilterScope,
	route, backend, mcpMethod, tool string,
	headers http.Header,
	body []byte,
) (newBody []byte, rejected bool, reason string, err error) {
	env := contentFilterRequest{
		Route:       route,
		Backend:     backend,
		Scope:       string(scope),
		MCPMethod:   mcpMethod,
		Tool:        tool,
		Headers:     cf.selectHeaders(headers),
		BodyBase64:  base64.StdEncoding.EncodeToString(body),
		ContentType: "application/json",
	}
	envBytes, mErr := json.Marshal(env)
	if mErr != nil {
		return nil, false, "", fmt.Errorf("marshal content filter request: %w", mErr)
	}

	callCtx, cancel := context.WithTimeout(ctx, cf.timeout)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(callCtx, http.MethodPost, cf.url, bytes.NewReader(envBytes))
	if reqErr != nil {
		return nil, false, "", fmt.Errorf("build content filter request: %w", reqErr)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, doErr := client.Do(req)
	if doErr != nil {
		return nil, false, "", fmt.Errorf("invoke content filter: %w", doErr)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, false, "", fmt.Errorf("content filter returned HTTP %d", resp.StatusCode)
	}

	respBytes, rErr := io.ReadAll(io.LimitReader(resp.Body, contentFilterMaxBodyBytes+1))
	if rErr != nil {
		return nil, false, "", fmt.Errorf("read content filter response: %w", rErr)
	}
	if len(respBytes) > contentFilterMaxBodyBytes {
		return nil, false, "", fmt.Errorf("content filter response exceeds %d bytes", contentFilterMaxBodyBytes)
	}

	var decoded contentFilterResponse
	if uErr := json.Unmarshal(respBytes, &decoded); uErr != nil {
		return nil, false, "", fmt.Errorf("decode content filter response: %w", uErr)
	}

	switch decoded.Action {
	case contentFilterActionPass:
		return body, false, "", nil
	case contentFilterActionReject:
		return nil, true, decoded.Reason, nil
	case contentFilterActionRedact:
		if decoded.BodyBase64 == "" {
			return nil, false, "", errors.New("content filter redact response missing bodyBase64")
		}
		replaced, decErr := base64.StdEncoding.DecodeString(decoded.BodyBase64)
		if decErr != nil {
			return nil, false, "", fmt.Errorf("decode content filter replacement body: %w", decErr)
		}
		return replaced, false, decoded.Reason, nil
	default:
		return nil, false, "", fmt.Errorf("content filter returned unknown action %q", decoded.Action)
	}
}

// selectHeaders copies the configured forward headers from src into a
// canonicalised map. Header values are always slices per http.Header
// semantics. An empty or missing header is omitted from the output.
func (cf *contentFilter) selectHeaders(src http.Header) map[string][]string {
	if len(cf.forwardHeadersCanonical) == 0 || src == nil {
		return map[string][]string{}
	}
	out := make(map[string][]string, len(cf.forwardHeadersCanonical))
	for _, h := range cf.forwardHeadersCanonical {
		if values := src.Values(h); len(values) > 0 {
			out[h] = append([]string(nil), values...)
		}
	}
	return out
}

// applyContentFilterOnRequest invokes the filter at Request scope. On
// success it returns the (possibly rewritten) JSON-RPC request params bytes.
// On reject it returns errContentFilterRejected wrapping the filter's reason.
// On failure it returns errContentFilterFailed when the filter is
// fail-closed, or a nil error and the original body when fail-open.
//
// This is a thin wrapper over [applyContentFilterOnRequestWithStatus]
// preserved for existing callers that do not need the per-call status
// value (unit tests). New callers should use the WithStatus variant so
// the X-Content-Filter-Status header and mcp_filter_status_total
// counter can be emitted on the proxied response.
func applyContentFilterOnRequest(
	ctx context.Context,
	l *mcpLoggerShim,
	client *http.Client,
	cf *contentFilter,
	routeName filterapi.MCPRouteName,
	backendName filterapi.MCPBackendName,
	tool string,
	req *jsonrpc.Request,
	headers http.Header,
) (*jsonrpc.Request, error) {
	out, _, err := applyContentFilterOnRequestWithStatus(ctx, l, client, cf,
		routeName, backendName, tool, req, headers)
	return out, err
}

// applyContentFilterOnRequestWithStatus is the status-aware form of
// [applyContentFilterOnRequest]. It additionally returns a canonical
// [FilterStatus] for every code path so that the HTTP handler can:
//
//  1. Set the X-Content-Filter-Status response header exactly once
//     per proxied response.
//  2. Emit the mcp_filter_status_total counter through the installed
//     Prometheus observer.
//
// The status is always populated regardless of error. Status/err
// combinations:
//
//	(FilterStatusOff,          nil)                         - no filter configured for this scope
//	(FilterStatusPass,         nil)                         - filter ran, body unchanged
//	(FilterStatusRedact,       nil)                         - filter ran, body rewritten
//	(FilterStatusReject,       errContentFilterRejected...)  - filter blocked the call
//	(FilterStatusUnavailable,  errContentFilterFailed...)    - filter errored, fail-closed
//	(FilterStatusFailedOpen,   nil)                         - filter errored, fail-open; original body forwarded
//	(FilterStatusUnavailable,  <other err>)                 - decode/encode/contract failures (always counted as unavailable)
func applyContentFilterOnRequestWithStatus(
	ctx context.Context,
	l *mcpLoggerShim,
	client *http.Client,
	cf *contentFilter,
	routeName filterapi.MCPRouteName,
	backendName filterapi.MCPBackendName,
	tool string,
	req *jsonrpc.Request,
	headers http.Header,
) (*jsonrpc.Request, FilterStatus, error) {
	if cf == nil || !cf.invokeOnRequest {
		return req, FilterStatusOff, nil
	}
	// Gate 1: kill switch. When GlobalDisable (process-wide) or
	// Enabled=false (per-backend) is set we forward the original
	// body without contacting the filter and emit status=disabled
	// so dashboards can distinguish "off" (no filter configured)
	// from "disabled" (configured but suppressed).
	if cf.isDisabled() {
		emitShadowDecision(routeName, backendName, ScopeRequest, contentFilterActionDisabled)
		emitShadowAudit(ctx, routeName, backendName, tool, contentFilterActionDisabled, "", 0, 0, 0)
		return req, FilterStatusDisabled, nil
	}
	// Gate 2: shadow-mode sampling. When the per-backend
	// ShadowSampleRatePermille excludes this call we skip the
	// upstream filter entirely and record action=shadow_sampled_out
	// so operators can size budgets against real traffic volumes.
	if cf.effectiveMode() == filterapi.MCPContentFilterModeShadow && !cf.sampleThisShadowCall() {
		emitShadowDecision(routeName, backendName, ScopeRequest, contentFilterActionShadowSampledOut)
		emitShadowAudit(ctx, routeName, backendName, tool, contentFilterActionShadowSampledOut, "", 0, 0, 0)
		return req, FilterStatusPass, nil
	}
	body, err := jsonrpc.EncodeMessage(req)
	if err != nil {
		return nil, FilterStatusUnavailable, fmt.Errorf("encode JSON-RPC request for content filter: %w", err)
	}

	var (
		newBody   []byte
		rejected  bool
		reason    string
		invokeErr error
		started   = time.Now()
	)
	// Prefer in-process dispatch when a dispatcher is wired up; fall
	// back to the HTTP sidecar path otherwise. The two branches are
	// observationally equivalent: each returns (newBody, rejected,
	// reason, err) with identical semantics.
	if cf.dispatcher != nil {
		newBody, rejected, reason, invokeErr = dispatchInProcess(ctx, cf.dispatcher,
			ScopeRequest, routeName, backendName, req.Method, tool, headers, body)
	} else {
		newBody, rejected, reason, invokeErr = cf.invoke(ctx, client, contentFilterScopeRequest,
			routeName, backendName, req.Method, tool, headers, body)
	}
	elapsed := time.Since(started)

	// Shadow-mode branch: never apply the verdict, always forward
	// the original body. We still record WHAT the filter WOULD
	// have done so operators can A/B against enforce-mode traffic.
	if cf.effectiveMode() == filterapi.MCPContentFilterModeShadow {
		if invokeErr != nil {
			l.warn("content filter request invocation failed in shadow mode",
				"route", routeName, "backend", backendName, "tool", tool, "err", invokeErr.Error())
			emitShadowDecision(routeName, backendName, ScopeRequest, contentFilterActionShadowWouldFail)
			emitShadowAudit(ctx, routeName, backendName, tool, contentFilterActionShadowWouldFail, invokeErr.Error(), len(body), 0, elapsed)
			return req, FilterStatusPass, nil
		}
		verdict := shadowBodyVerdict(body, newBody, rejected)
		emitShadowDecision(routeName, backendName, ScopeRequest, verdict)
		emitShadowAudit(ctx, routeName, backendName, tool, verdict, reason, len(body), len(newBody), elapsed)
		return req, FilterStatusPass, nil
	}

	if invokeErr != nil {
		l.warn("content filter request invocation failed",
			"route", routeName, "backend", backendName, "tool", tool, "err", invokeErr.Error())
		if cf.failClosed {
			return nil, FilterStatusUnavailable, errors.Join(errContentFilterFailed, invokeErr)
		}
		return req, FilterStatusFailedOpen, nil
	}
	if rejected {
		return nil, FilterStatusReject, fmt.Errorf("%w: %s", errContentFilterRejected, reason)
	}
	if bytes.Equal(newBody, body) {
		return req, FilterStatusPass, nil
	}
	msg, ok := tryDecodeJSONRPCMessage(newBody)
	if !ok {
		return nil, FilterStatusUnavailable, fmt.Errorf("content filter returned replacement body that is not valid JSON-RPC")
	}
	replaced, ok := msg.(*jsonrpc.Request)
	if !ok {
		return nil, FilterStatusUnavailable, fmt.Errorf("content filter returned replacement body that is not a JSON-RPC request")
	}
	replaced.ID = req.ID
	if replaced.Method == "" {
		replaced.Method = req.Method
	}
	return replaced, FilterStatusRedact, nil
}

// applyContentFilterOnResponse invokes the filter at Response scope and
// returns the possibly rewritten JSON-RPC response. On reject it returns
// errContentFilterRejected. On failure it returns errContentFilterFailed
// when the filter is fail-closed, or the original response otherwise.
//
// This is a thin wrapper over [applyContentFilterOnResponseWithStatus]
// preserved for existing callers that do not need the per-call status
// value (unit tests). New callers should use the WithStatus variant so
// the X-Content-Filter-Status header and mcp_filter_status_total
// counter can be emitted on the proxied response.
func applyContentFilterOnResponse(
	ctx context.Context,
	l *mcpLoggerShim,
	client *http.Client,
	cf *contentFilter,
	routeName filterapi.MCPRouteName,
	backendName filterapi.MCPBackendName,
	tool string,
	req *jsonrpc.Request,
	resp *jsonrpc.Response,
	headers http.Header,
) (*jsonrpc.Response, error) {
	out, _, err := applyContentFilterOnResponseWithStatus(ctx, l, client, cf,
		routeName, backendName, tool, req, resp, headers)
	return out, err
}

// applyContentFilterOnResponseWithStatus is the status-aware form of
// [applyContentFilterOnResponse]. Contract mirrors
// [applyContentFilterOnRequestWithStatus]: the status is always
// populated; combinations with errors match the request path.
func applyContentFilterOnResponseWithStatus(
	ctx context.Context,
	l *mcpLoggerShim,
	client *http.Client,
	cf *contentFilter,
	routeName filterapi.MCPRouteName,
	backendName filterapi.MCPBackendName,
	tool string,
	req *jsonrpc.Request,
	resp *jsonrpc.Response,
	headers http.Header,
) (*jsonrpc.Response, FilterStatus, error) {
	if cf == nil || !cf.invokeOnResponse {
		return resp, FilterStatusOff, nil
	}
	// Gate 1: kill switch — identical semantics to the Request path.
	if cf.isDisabled() {
		emitShadowDecision(routeName, backendName, ScopeResponse, contentFilterActionDisabled)
		emitShadowAudit(ctx, routeName, backendName, tool, contentFilterActionDisabled, "", 0, 0, 0)
		return resp, FilterStatusDisabled, nil
	}
	// Gate 2: shadow-mode sampling — skipped calls emit
	// action=shadow_sampled_out and forward the original body.
	if cf.effectiveMode() == filterapi.MCPContentFilterModeShadow && !cf.sampleThisShadowCall() {
		emitShadowDecision(routeName, backendName, ScopeResponse, contentFilterActionShadowSampledOut)
		emitShadowAudit(ctx, routeName, backendName, tool, contentFilterActionShadowSampledOut, "", 0, 0, 0)
		return resp, FilterStatusPass, nil
	}
	body, err := jsonrpc.EncodeMessage(resp)
	if err != nil {
		return nil, FilterStatusUnavailable, fmt.Errorf("encode JSON-RPC response for content filter: %w", err)
	}
	method := ""
	if req != nil {
		method = req.Method
	}

	var (
		newBody   []byte
		rejected  bool
		reason    string
		invokeErr error
		started   = time.Now()
	)
	// Same branch as the request path: dispatcher wins when present,
	// HTTP sidecar is the fallback.
	if cf.dispatcher != nil {
		newBody, rejected, reason, invokeErr = dispatchInProcess(ctx, cf.dispatcher,
			ScopeResponse, routeName, backendName, method, tool, headers, body)
	} else {
		newBody, rejected, reason, invokeErr = cf.invoke(ctx, client, contentFilterScopeResponse,
			routeName, backendName, method, tool, headers, body)
	}
	elapsed := time.Since(started)

	// Shadow-mode branch: forward the original response, record
	// what WOULD have happened. Shadow is never fail-closed: we do
	// not want filter outages during rollout to start rejecting
	// traffic.
	if cf.effectiveMode() == filterapi.MCPContentFilterModeShadow {
		if invokeErr != nil {
			l.warn("content filter response invocation failed in shadow mode",
				"route", routeName, "backend", backendName, "tool", tool, "err", invokeErr.Error())
			emitShadowDecision(routeName, backendName, ScopeResponse, contentFilterActionShadowWouldFail)
			emitShadowAudit(ctx, routeName, backendName, tool, contentFilterActionShadowWouldFail, invokeErr.Error(), len(body), 0, elapsed)
			return resp, FilterStatusPass, nil
		}
		verdict := shadowBodyVerdict(body, newBody, rejected)
		emitShadowDecision(routeName, backendName, ScopeResponse, verdict)
		emitShadowAudit(ctx, routeName, backendName, tool, verdict, reason, len(body), len(newBody), elapsed)
		return resp, FilterStatusPass, nil
	}

	if invokeErr != nil {
		l.warn("content filter response invocation failed",
			"route", routeName, "backend", backendName, "tool", tool, "err", invokeErr.Error())
		if cf.failClosed {
			return nil, FilterStatusUnavailable, errors.Join(errContentFilterFailed, invokeErr)
		}
		return resp, FilterStatusFailedOpen, nil
	}
	if rejected {
		return nil, FilterStatusReject, fmt.Errorf("%w: %s", errContentFilterRejected, reason)
	}
	if bytes.Equal(newBody, body) {
		return resp, FilterStatusPass, nil
	}
	msg, ok := tryDecodeJSONRPCMessage(newBody)
	if !ok {
		return nil, FilterStatusUnavailable, fmt.Errorf("content filter returned replacement body that is not valid JSON-RPC")
	}
	replaced, ok := msg.(*jsonrpc.Response)
	if !ok {
		return nil, FilterStatusUnavailable, fmt.Errorf("content filter returned replacement body that is not a JSON-RPC response")
	}
	if resp != nil {
		replaced.ID = resp.ID
	}
	return replaced, FilterStatusRedact, nil
}

// mcpLoggerShim is a tiny adapter so that content filter code can log
// without taking a direct dependency on log/slog's variadic signature; it
// exists to keep the invocation helpers testable without a real logger.
type mcpLoggerShim struct {
	warnFunc func(msg string, kv ...any)
}

func (l *mcpLoggerShim) warn(msg string, kv ...any) {
	if l == nil || l.warnFunc == nil {
		return
	}
	l.warnFunc(msg, kv...)
}
