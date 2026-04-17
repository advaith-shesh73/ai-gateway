// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Per-backend handlers — DefaultHandler, SupportGPTHandler, NuRAGHandler,
// GleanHandler, JiraHandler. Each mirrors the Python implementation in
// panacea-agent/services/aigw-content-filter/app/backends/*.py one-for-one;
// divergences are called out inline.
//
// Design notes:
//   - Handlers are stateless (fields are configuration, not per-request
//     state) so the dispatcher can share a single instance across
//     goroutines.
//   - Every PII-fallback path goes through the shared runPIIScan helper
//     so fail-open/fail-closed symmetry cannot drift between handlers.
//   - REDACT_TAG, tool sets, and regex constants are package-level so
//     parity audits can grep for literal strings across Go and Python.
//   - Encoding is via json.Marshal (not encoding/json with indent) to
//     match Python's `json.dumps(..., separators=(",", ":"))`.

import (
	"context"
	"encoding/json" // nolint: depguard // json.Number / json.MarshalIndent not exposed by internal/json.
	"errors"
	"log/slog"
	"regexp"
	"strings"
)

// REDACTEvalTicketTag is the literal replacement for any verbatim
// occurrence of the eval ticket ID inside a SupportGPT response. The
// string matches the Python REDACT_TAG in app/backends/supportgpt.py so
// downstream consumers that already learned the Python tag keep matching.
const REDACTEvalTicketTag = "[REDACTED_EVAL_TICKET]"

// --- tool name sets ------------------------------------------------------
//
// These sets are frozenset-equivalents from the Python backends. Using a
// map[string]struct{} because Go has no native set type and we care about
// O(1) membership tests in the hot path.

// supportGPTExcludeSearchTools mirrors EXCLUDE_SEARCH_TOOLS in
// app/backends/supportgpt.py. Any addition must be made in lockstep there.
var supportGPTExcludeSearchTools = map[string]struct{}{
	"find_similar_rcas":      {},
	"search_cases":           {},
	"extract_tickets":        {},
	"search_support_tickets": {},
	"search_knowledge":       {},
}

// nuragQueryTools mirrors QUERY_TOOLS in app/backends/nurag.py.
var nuragQueryTools = map[string]struct{}{
	"query_knowledge":  {},
	"search_knowledge": {},
	"search_documents": {},
	"query_rag":        {},
	"ask_nurag":        {},
}

// gleanSearchTools mirrors SEARCH_TOOLS in app/backends/glean.py.
var gleanSearchTools = map[string]struct{}{
	"search":           {},
	"glean_search":     {},
	"search_documents": {},
}

// jiraGetIssueTools mirrors GET_ISSUE_TOOLS in app/backends/jira.py.
var jiraGetIssueTools = map[string]struct{}{
	"getJiraIssue":   {},
	"get_jira_issue": {},
	"jira_get_issue": {},
}

// jiraSearchJQLTools mirrors SEARCH_JQL_TOOLS in app/backends/jira.py.
var jiraSearchJQLTools = map[string]struct{}{
	"searchJiraIssuesUsingJql":     {},
	"search_jira_issues_using_jql": {},
	"jira_search":                  {},
}

// ticketKeyRegex matches ABC-123 style Jira ticket keys. Mirrors
// TICKET_ID_RE in app/backends/nurag.py; the NuRAG handler uses it to
// decide whether to inject exclude_sources.
var ticketKeyRegex = regexp.MustCompile(`^[A-Z][A-Z0-9]+-\d+$`)

// --- shared helpers ------------------------------------------------------

// runPIIScan is the shared PII-fallback path every handler uses after
// resolving any backend-specific mutations. It returns one of three
// FilterResponse flavors:
//   - ActionPass when the response has no text parts, the PII client
//     detected no redactions, or the PII client is nil (PII handler
//     disabled).
//   - ActionRedact with a rebuilt body when at least one text part was
//     modified.
//   - ActionReject with code CodePIIUnavailable when the PII client
//     returned a *PIIServiceError (fail-closed path).
//
// The preprocessor is applied per-part before the PII call and is
// typically SubstringScrubber(ticket, REDACTEvalTicketTag) for SupportGPT.
// Passing nil preprocessor is legal and skips the pre-step.
//
// The context parameter is the ambient request context; cancellation
// propagates into the PIIClient's http.Client via ScanTextParts.
func runPIIScan(
	ctx context.Context,
	handlerName string,
	req *FilterRequest,
	body any,
	deps HandlerContext,
	preprocess TextPreprocessor,
) FilterResponse {
	result := ResponseResult(body)
	parts := IterTextParts(result)
	if len(parts) == 0 {
		return PassResponse(handlerName + ": no text parts in response")
	}
	if deps.PII == nil {
		// PII client wasn't provided — treat as pass. This is only
		// reached when EnableDefaultPII=false AND a handler that
		// normally wants PII fallback is still registered; the
		// policy validator should prevent it but we refuse to panic.
		return PassResponse(handlerName + ": PII disabled")
	}

	piiContext := BuildPIIContext(req.Scope, req.Route, req.Backend, req.Tool)
	scanInputs := make([]TextPartInput, 0, len(parts))
	for _, p := range parts {
		scanInputs = append(scanInputs, TextPartInput(p))
	}
	anonymize := func(ctx context.Context, text string) (string, error) {
		return deps.PII.AnonymizeForRoute(ctx, text, piiContext, req.Route, req.Backend)
	}
	maxParts := 1
	if deps.Policy != nil && deps.Policy.PII.MaxParallelParts > 0 {
		maxParts = deps.Policy.PII.MaxParallelParts
	}
	replacements, err := ScanTextParts(ctx, scanInputs, anonymize, maxParts, preprocess)
	if err != nil {
		var piiErr *PIIServiceError
		if errors.As(err, &piiErr) {
			return RejectResponse(
				handlerName+": pii service unavailable: "+piiErr.Error(),
				CodePIIUnavailable,
				msgPIIRedactionRequired,
			)
		}
		// Any non-PII error (e.g. context cancellation mid-fan-out)
		// falls through to a policy reject with the default code.
		return RejectResponse(
			handlerName+": scan failed: "+err.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	if len(replacements) == 0 {
		return PassResponse(handlerName + ": no pii detected")
	}

	newResult := WithTextParts(result, replacements)
	newBody := WithResponseResult(body, newResult)
	encoded, encErr := marshalBody(newBody)
	if encErr != nil {
		return RejectResponse(
			handlerName+": body encode failed: "+encErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	return RedactResponse(encoded, handlerName+": redacted text parts")
}

// marshalBody compact-JSON-encodes a body mutation. Mirrors Python's
// `json.dumps(..., separators=(",", ":"))`. Centralized so every handler
// uses the same encoding contract.
func marshalBody(v any) ([]byte, error) {
	return json.Marshal(v)
}

// normalizeExcludeList mirrors _normalize_exclude_list in
// app/backends/supportgpt.py. Accepts nil / list / string / scalar and
// returns a []string with whitespace trimmed and empty entries dropped.
func normalizeExcludeList(value any) []string {
	if value == nil {
		return nil
	}
	switch v := value.(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			s := strings.TrimSpace(anyToString(item))
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		out := make([]string, 0, len(v))
		for _, s := range v {
			s = strings.TrimSpace(s)
			if s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		out := make([]string, 0, strings.Count(v, ",")+1)
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
		return out
	default:
		s := strings.TrimSpace(anyToString(v))
		if s == "" {
			return nil
		}
		return []string{s}
	}
}

// anyToString is the equivalent of Python's str(v) for JSON-unmarshaled
// values. Lives here (and not in mcp_utils.go) because it is only used
// by the backend handlers.
func anyToString(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		if x {
			return "true"
		}
		return "false"
	case json.Number:
		return x.String()
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// containsString reports whether s appears in slice. Used by handlers'
// idempotency checks (e.g. SupportGPT skips mutation when the ticket is
// already on the exclude list).
func containsString(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// --- DefaultHandler ------------------------------------------------------

// DefaultHandler is the fallback handler that runs PII scan on the
// response scope and passes the request scope through unchanged.
// Mirrors app/backends/default.py:DefaultHandler.
type DefaultHandler struct {
	BaseHandler
	// piiScanBackends is the lowercased set of backend names whose
	// response bodies should be PII-scanned by this handler. Other
	// backends fall through to an unconditional pass.
	piiScanBackends map[string]struct{}
}

// NewDefaultHandler constructs a DefaultHandler with the given PII-scan
// backend allowlist.
func NewDefaultHandler(piiScanBackends []string) *DefaultHandler {
	set := make(map[string]struct{}, len(piiScanBackends))
	for _, name := range piiScanBackends {
		set[strings.ToLower(name)] = struct{}{}
	}
	return &DefaultHandler{
		BaseHandler:     BaseHandler{HandlerName: "default"},
		piiScanBackends: set,
	}
}

// HandleResponse runs a PII scan when the backend is in piiScanBackends,
// otherwise passes through.
func (h *DefaultHandler) HandleResponse(
	ctx context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	backendLower := strings.ToLower(req.Backend)
	if _, ok := h.piiScanBackends[backendLower]; !ok {
		return PassResponse(h.Name() + ": backend " + req.Backend + " not in PII scan set")
	}
	return runPIIScan(ctx, h.Name(), req, body, deps, nil)
}

// --- SupportGPTHandler ---------------------------------------------------

// SupportGPTHandler injects exclude_ticket_ids into SupportGPT search
// tools on request, and runs a substring-scrub + PII scan on response.
//
// Parity: mirrors app/backends/supportgpt.py:SupportGPTHandler.
type SupportGPTHandler struct {
	BaseHandler
}

// NewSupportGPTHandler constructs a SupportGPTHandler with canonical name.
func NewSupportGPTHandler() *SupportGPTHandler {
	return &SupportGPTHandler{BaseHandler: BaseHandler{HandlerName: "supportgpt"}}
}

// HandleRequest injects exclude_ticket_ids on EXCLUDE_SEARCH_TOOLS when
// eval mode is active. Non-eval or non-matching tools pass through.
func (h *SupportGPTHandler) HandleRequest(
	_ context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	ticket, err := resolveEvalTicket(req, deps)
	if err != nil {
		return evalTicketError(h.Name(), err)
	}
	if ticket == "" {
		return PassResponse(h.Name() + ": eval mode inactive")
	}

	if _, ok := supportGPTExcludeSearchTools[req.Tool]; !ok {
		return PassResponse(h.Name() + ": tool " + req.Tool + " has no exclude rule")
	}

	args := ToolArguments(body)
	existing := normalizeExcludeList(args["exclude_ticket_ids"])
	if containsString(existing, ticket) {
		return PassResponse(h.Name() + ": " + ticket + " already excluded")
	}
	newArgs := make(map[string]any, len(args)+1)
	for k, v := range args {
		newArgs[k] = v
	}
	// Python appends [ticket] to the existing list. We preserve order
	// and type so the downstream tool does not see a surprise shape.
	merged := make([]any, 0, len(existing)+1)
	for _, s := range existing {
		merged = append(merged, s)
	}
	merged = append(merged, ticket)
	newArgs["exclude_ticket_ids"] = merged

	newBody := WithToolArguments(body, newArgs)
	encoded, encErr := marshalBody(newBody)
	if encErr != nil {
		return RejectResponse(
			h.Name()+": body encode failed: "+encErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	return RedactResponse(
		encoded,
		h.Name()+": injected exclude_ticket_ids="+ticket,
	)
}

// HandleResponse runs a substring scrub (if eval mode) + PII scan.
func (h *SupportGPTHandler) HandleResponse(
	ctx context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	ticket, err := resolveEvalTicket(req, deps)
	if err != nil {
		return evalTicketError(h.Name(), err)
	}
	var pre TextPreprocessor
	if ticket != "" {
		pre = SubstringScrubber(ticket, REDACTEvalTicketTag)
	}
	return runPIIScan(ctx, h.Name(), req, body, deps, pre)
}

// --- NuRAGHandler --------------------------------------------------------

// NuRAGHandler injects exclude_sources on knowledge-query tools when the
// eval ticket looks like a ticket key (ABC-123).
//
// Parity: mirrors app/backends/nurag.py:NuRAGHandler.
type NuRAGHandler struct {
	BaseHandler
}

// NewNuRAGHandler constructs a NuRAGHandler.
func NewNuRAGHandler() *NuRAGHandler {
	return &NuRAGHandler{BaseHandler: BaseHandler{HandlerName: "nurag"}}
}

// HandleRequest merges ticket into arguments.exclude_sources when in
// eval mode AND the tool is in QUERY_TOOLS AND the ticket matches the
// ABC-123 regex.
func (h *NuRAGHandler) HandleRequest(
	_ context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	ticket, err := resolveEvalTicket(req, deps)
	if err != nil {
		return evalTicketError(h.Name(), err)
	}
	if ticket == "" {
		return PassResponse(h.Name() + ": eval mode inactive")
	}
	if !ticketKeyRegex.MatchString(ticket) {
		return PassResponse(h.Name() + ": " + ticket + " is not a ticket key")
	}
	if _, ok := nuragQueryTools[req.Tool]; !ok {
		return PassResponse(h.Name() + ": tool " + req.Tool + " has no exclude rule")
	}

	args := ToolArguments(body)
	existingRaw := args["exclude_sources"]
	existing := normalizeExcludeList(existingRaw)
	if containsString(existing, ticket) {
		return PassResponse(h.Name() + ": " + ticket + " already excluded")
	}

	newArgs := make(map[string]any, len(args)+1)
	for k, v := range args {
		newArgs[k] = v
	}
	merged := make([]any, 0, len(existing)+1)
	for _, s := range existing {
		merged = append(merged, s)
	}
	merged = append(merged, ticket)
	newArgs["exclude_sources"] = merged

	newBody := WithToolArguments(body, newArgs)
	encoded, encErr := marshalBody(newBody)
	if encErr != nil {
		return RejectResponse(
			h.Name()+": body encode failed: "+encErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	return RedactResponse(
		encoded,
		h.Name()+": injected exclude_sources+="+ticket,
	)
}

// HandleResponse runs PII scan without any preprocessor.
func (h *NuRAGHandler) HandleResponse(
	ctx context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	return runPIIScan(ctx, h.Name(), req, body, deps, nil)
}

// --- GleanHandler --------------------------------------------------------

// GleanHandler appends a `-ticket:<id>` exclusion to the Glean query
// string when eval mode is active and the tool is a search tool.
//
// Parity: mirrors app/backends/glean.py:GleanHandler.
type GleanHandler struct {
	BaseHandler
}

// NewGleanHandler constructs a GleanHandler.
func NewGleanHandler() *GleanHandler {
	return &GleanHandler{BaseHandler: BaseHandler{HandlerName: "glean"}}
}

// HandleRequest appends `-ticket:<id>` to either `query` or `q`.
func (h *GleanHandler) HandleRequest(
	_ context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	ticket, err := resolveEvalTicket(req, deps)
	if err != nil {
		return evalTicketError(h.Name(), err)
	}
	if ticket == "" {
		return PassResponse(h.Name() + ": eval mode inactive")
	}
	if _, ok := gleanSearchTools[req.Tool]; !ok {
		return PassResponse(h.Name() + ": tool " + req.Tool + " has no exclusion rule")
	}

	args := ToolArguments(body)
	key := gleanQueryKey(args)
	currentStr, _ := args[key].(string)
	exclusion := "-ticket:" + ticket
	if strings.Contains(currentStr, exclusion) {
		return PassResponse(h.Name() + ": exclusion already present")
	}
	var newQuery string
	if currentStr == "" {
		newQuery = exclusion
	} else {
		newQuery = strings.TrimSpace(currentStr + " " + exclusion)
	}

	newArgs := make(map[string]any, len(args)+1)
	for k, v := range args {
		newArgs[k] = v
	}
	newArgs[key] = newQuery

	newBody := WithToolArguments(body, newArgs)
	encoded, encErr := marshalBody(newBody)
	if encErr != nil {
		return RejectResponse(
			h.Name()+": body encode failed: "+encErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	return RedactResponse(encoded, h.Name()+": appended "+exclusion+" to "+key)
}

// HandleResponse runs PII scan without any preprocessor.
func (h *GleanHandler) HandleResponse(
	ctx context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	return runPIIScan(ctx, h.Name(), req, body, deps, nil)
}

// gleanQueryKey picks whichever of "query"/"q" is populated with a
// non-empty string. Falls back to whichever key is present (even as an
// empty string), and finally defaults to "query" when neither key
// appears. Matches the Python selector _query_key_from_args.
func gleanQueryKey(args map[string]any) string {
	if s, ok := args["query"].(string); ok && s != "" {
		return "query"
	}
	if s, ok := args["q"].(string); ok && s != "" {
		return "q"
	}
	if _, ok := args["query"]; ok {
		return "query"
	}
	if _, ok := args["q"]; ok {
		return "q"
	}
	return "query"
}

// --- JiraHandler ---------------------------------------------------------

// JiraHandler rewrites JQL on request, T0-reconstructs issues on
// response, and falls back to PII scan when neither applies.
//
// Parity: mirrors app/backends/jira.py:JiraHandler.
type JiraHandler struct {
	BaseHandler
}

// NewJiraHandler constructs a JiraHandler.
func NewJiraHandler() *JiraHandler {
	return &JiraHandler{BaseHandler: BaseHandler{HandlerName: "jira"}}
}

// HandleRequest rewrites JQL on searchJiraIssuesUsingJql-class tools.
// Non-JQL tools pass through.
func (h *JiraHandler) HandleRequest(
	_ context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	ticket, err := resolveEvalTicket(req, deps)
	if err != nil {
		return evalTicketError(h.Name(), err)
	}
	if ticket == "" {
		return PassResponse(h.Name() + ": eval mode inactive")
	}
	if _, ok := jiraSearchJQLTools[req.Tool]; !ok {
		return PassResponse(h.Name() + ": request scope no-op for " + req.Tool)
	}

	args := ToolArguments(body)
	key, current := jqlFromArgs(args)
	rewritten := RewriteJQLExcluding(current, ticket)
	if rewritten == current {
		return PassResponse(h.Name() + ": JQL already excludes " + ticket)
	}
	newArgs := make(map[string]any, len(args)+1)
	for k, v := range args {
		newArgs[k] = v
	}
	newArgs[key] = rewritten

	newBody := WithToolArguments(body, newArgs)
	encoded, encErr := marshalBody(newBody)
	if encErr != nil {
		return RejectResponse(
			h.Name()+": body encode failed: "+encErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	return RedactResponse(
		encoded,
		h.Name()+": rewrote "+key+" to exclude "+ticket,
	)
}

// HandleResponse: if eval mode is active AND the tool is a get-issue
// tool AND the target matches the eval ticket, perform T0 reconstruction.
// Otherwise fall through to PII scan.
func (h *JiraHandler) HandleResponse(
	ctx context.Context,
	req *FilterRequest,
	body any,
	deps HandlerContext,
) FilterResponse {
	ticket, err := resolveEvalTicket(req, deps)
	if err != nil {
		return evalTicketError(h.Name(), err)
	}

	// T0 path only fires when we have: eval mode, get-issue tool, AND
	// a live Jira client. Missing any one of these falls through to PII.
	if ticket != "" {
		if _, ok := jiraGetIssueTools[req.Tool]; ok && deps.Jira != nil {
			target := jiraTargetKeyFromHeaders(req)
			if target == "" {
				target = guessTicketKeyFromResult(body)
			}
			if target == "" {
				target = ticket
			}
			if target == ticket {
				return h.serveT0(ctx, req, body, ticket, deps)
			}
		}
	}

	return runPIIScan(ctx, h.Name(), req, body, deps, nil)
}

// serveT0 fetches the issue + changelog, reconstructs T0 field values,
// and rebuilds the response body to contain only the T0 JSON.
func (h *JiraHandler) serveT0(
	ctx context.Context,
	_ *FilterRequest,
	body any,
	ticket string,
	deps HandlerContext,
) FilterResponse {
	issue, err := deps.Jira.FetchIssueWithChangelog(ctx, ticket)
	if err != nil {
		deps.Logger.ErrorContext(ctx, "jira T0 fetch failed",
			slog.String("handler", h.Name()),
			slog.String("ticket", ticket),
			slog.String("err", err.Error()),
		)
		return RejectResponse(
			h.Name()+": T0 reconstruction failed: "+err.Error(),
			CodeJiraUnavailable,
			msgJiraUnavailable,
		)
	}
	t0 := ReconstructT0(issue)
	t0JSON, jsonErr := json.MarshalIndent(t0, "", "  ")
	if jsonErr != nil {
		return RejectResponse(
			h.Name()+": T0 encode failed: "+jsonErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	// Rebuild result: one text part whose JSON body is the T0 object.
	rebuilt := map[string]any{
		"content": []any{
			map[string]any{
				"type": "text",
				"text": string(t0JSON),
			},
		},
		"isError": false,
	}
	newBody := WithResponseResult(body, rebuilt)
	encoded, encErr := marshalBody(newBody)
	if encErr != nil {
		return RejectResponse(
			h.Name()+": body encode failed: "+encErr.Error(),
			CodePolicyReject,
			msgContentPolicyViolation,
		)
	}
	return RedactResponse(encoded, h.Name()+": served T0 recreation for "+ticket)
}

// jiraTargetKeyFromHeaders extracts the requested ticket key from a
// gateway-forwarded header. The gateway copies the request arguments
// into x-aigwcf-request-arguments so the response handler can correlate
// the get-issue call with its input. Returns "" when the header is
// absent, malformed, or has no key-like field.
//
// Parity: mirrors the Python handler's re-parse of the forwarded JSON.
func jiraTargetKeyFromHeaders(req *FilterRequest) string {
	raw := req.Headers.Get("x-aigwcf-request-arguments")
	if raw == "" {
		return ""
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return ""
	}
	return ticketKeyFromArgs(ToolArguments(parsed))
}

// ticketKeyFromArgs returns the first recognized ticket-key-bearing
// argument value. Parity: _ticket_key_from_args in app/backends/jira.py.
func ticketKeyFromArgs(args map[string]any) string {
	for _, key := range []string{
		"issueIdOrKey", "issueKey", "issue_id_or_key", "issue_key", "key", "id",
	} {
		v, ok := args[key]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		s = strings.TrimSpace(s)
		if s != "" {
			return s
		}
	}
	return ""
}

// guessTicketKeyFromResult scans a response's text parts, attempts to
// parse each as JSON, and returns the first `"key": "ABC-123"` it finds.
// Mirrors _guess_ticket_key_from_result in app/backends/jira.py.
func guessTicketKeyFromResult(body any) string {
	result := ResponseResult(body)
	for _, part := range IterTextParts(result) {
		var parsed map[string]any
		if err := json.Unmarshal([]byte(part.Text), &parsed); err != nil {
			continue
		}
		key, ok := parsed["key"].(string)
		if !ok {
			continue
		}
		if strings.Contains(key, "-") {
			return key
		}
	}
	return ""
}

// jqlFromArgs returns (key, currentJQL) for the first argument named
// "jql" or "query". Mirrors _jql_from_args in app/backends/jira.py.
func jqlFromArgs(args map[string]any) (string, string) {
	if s, ok := args["jql"].(string); ok {
		return "jql", s
	}
	if s, ok := args["query"].(string); ok {
		return "query", s
	}
	return "jql", ""
}

// --- shared eval-ticket extraction --------------------------------------

// resolveEvalTicket is the common seam where every handler extracts the
// eval-ticket-id from the request headers. Keeping the logic here means
// strict-mode ambiguity handling and the default-header-name fallback
// never drift between handlers.
func resolveEvalTicket(req *FilterRequest, deps HandlerContext) (string, error) {
	headerName := "x-eval-exclude-ticket-id"
	strict := false
	if deps.Policy != nil {
		if deps.Policy.Eval.Name != "" {
			headerName = deps.Policy.Eval.Name
		}
		strict = deps.Policy.Eval.Strict
	}
	return req.EvalTicketID(headerName, strict)
}

// evalTicketError converts a MultiValueEvalHeaderError into a reject
// with CodeInvalidRequest. Any other error is propagated as a reject
// with the default code.
func evalTicketError(handlerName string, err error) FilterResponse {
	var mv *MultiValueEvalHeaderError
	if errors.As(err, &mv) {
		return RejectResponse(
			handlerName+": "+err.Error(),
			CodeInvalidRequest,
			msgInvalidRequest,
		)
	}
	return RejectResponse(
		handlerName+": eval header extraction failed: "+err.Error(),
		CodePolicyReject,
		msgContentPolicyViolation,
	)
}
