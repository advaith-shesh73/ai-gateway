// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Jira Cloud client for T0 (creation-time) ticket reconstruction.
//
// Parity reference: panacea-agent/services/aigw-content-filter/app/jira_client.py
//
// Replays the ticket's changelog in reverse from the *current* field values
// to derive the values that were present at `created`. Fields that cannot
// be reconstructed safely (comments, worklog, status transitions,
// resolution) are dropped entirely — we never guess.
//
// The Jira Cloud REST API endpoint we rely on is:
//
//   GET /rest/api/3/issue/{id}?expand=changelog,names,renderedFields
//
// Changelog pagination: Jira returns up to 100 histories per page; for
// tickets with more changes we follow changelog.startAt + maxResults < total.
//
// Reliability
// -----------
//
// Each fetch goes through a circuit breaker. When Jira starts throwing 5xx
// or timing out we stop piling on after FailureThreshold errors — the
// breaker opens and subsequent calls raise JiraClientError with a
// "circuit_open" outcome so the dispatcher can immediately reject the T0
// reconstruction request rather than waiting for a timeout on every call.
// The breaker is reused across pagination pages of one request, but is
// *not* shared with the PII client (separate pools, separate thresholds —
// a slow Jira must not poison PII redactions; HANDOFF §4.10).

import (
	"context"
	"encoding/base64"
	"encoding/json" // nolint: depguard // json.Number required for JSON-decoded numeric type switch.
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/logsafe"
)

// T0FieldWhitelist is the set of creation-time fields we keep in a
// recreated ticket. Anything not in this set is dropped from the
// response. The list intentionally excludes comments, worklog, status,
// resolution, and fixVersions which encode post-creation information.
//
// Parity: this set MUST match app/jira_client.py:T0_FIELD_WHITELIST
// element-for-element. A divergence silently drops a field, breaking
// downstream consumers that still understand the schema.
var T0FieldWhitelist = map[string]struct{}{
	"summary":     {},
	"description": {},
	"reporter":    {},
	"creator":     {},
	"created":     {},
	"issuetype":   {},
	"project":     {},
	"priority":    {},
	"labels":      {},
	"components":  {},
	"environment": {},
	"versions":    {},
	"parent":      {},
	"duedate":     {},
}

// jiraOutcome labels the pii-equivalent metric series for the Jira path.
// Kept private because dispatcher mapping should happen inside this
// package; callers only see JiraClientError.
type jiraOutcome string

const (
	jiraOutcomeOK           jiraOutcome = "ok"
	jiraOutcomeCircuitOpen  jiraOutcome = "circuit_open"
	jiraOutcomeHTTPError    jiraOutcome = "http_error"
	jiraOutcomeDecodeError  jiraOutcome = "decode_error"
	jiraOutcomeTimeout      jiraOutcome = "timeout"
	jiraOutcomeNetworkError jiraOutcome = "network_error"
)

// JiraClientError is the sentinel error the Jira client returns when it
// cannot fulfil a reconstruction request. Dispatchers translate this
// into JSON-RPC code -32011 (dependency unavailable).
//
// Parity: mirrors app/jira_client.py:JiraClientError. Intentionally
// carries a machine-readable Outcome separate from the wrapped cause
// so metrics can pivot on outcome without parsing messages.
type JiraClientError struct {
	// Outcome is one of the jiraOutcome constants (e.g. "circuit_open",
	// "http_error"). Exposed as a string so callers can route on it
	// without importing the unexported type.
	Outcome string
	// IssueKey is the ticket we were trying to fetch when the error
	// occurred (may be empty for startup/config errors).
	IssueKey string
	// Err is the underlying cause (HTTP error, decode error, …). May
	// be nil when Outcome alone is informative (circuit open).
	Err error
}

// Error implements the error interface. The format mirrors the Python
// "jira fetch failed for X: <cause>" convention so existing log-parser
// rules keep matching after the port.
func (e *JiraClientError) Error() string {
	switch {
	case e.IssueKey != "" && e.Err != nil:
		return fmt.Sprintf("jira fetch failed for %s: %v", e.IssueKey, e.Err)
	case e.IssueKey != "":
		return fmt.Sprintf("jira fetch failed for %s: %s", e.IssueKey, e.Outcome)
	case e.Err != nil:
		return fmt.Sprintf("jira client: %s: %v", e.Outcome, e.Err)
	default:
		return fmt.Sprintf("jira client: %s", e.Outcome)
	}
}

// Unwrap lets callers use errors.Is/As on the underlying cause.
func (e *JiraClientError) Unwrap() error { return e.Err }

// JiraMetrics is the observer interface for the Jira client. Production
// wires this to the OTel registry so the historical Prometheus names
// (jira_calls_total, jira_call_duration_seconds) keep working.
//
// All callbacks are synchronous and on the hot path so implementations
// must not block.
type JiraMetrics interface {
	// RecordCall increments jira_calls_total{outcome, op}.
	RecordCall(outcome, op string)
	// ObserveCallDuration records jira_call_duration_seconds{op}.
	ObserveCallDuration(d time.Duration, op string)
}

type noopJiraMetrics struct{}

func (noopJiraMetrics) RecordCall(string, string)                 {}
func (noopJiraMetrics) ObserveCallDuration(time.Duration, string) {}

// JiraClientConfig bundles tunables for NewJiraClient. All zero values
// have sensible defaults applied inside the constructor.
type JiraClientConfig struct {
	// HTTPClient carries Jira requests. MUST be a dedicated client
	// (HANDOFF §4.10) — sharing with the PII client means a slow
	// Jira poll consumes a PII pool slot and vice versa.
	HTTPClient *http.Client
	// BaseURL is the Jira instance URL (e.g. "https://jira.example.com").
	// Trailing slash is tolerated. Required.
	BaseURL string
	// Email is the account email used for Basic auth. Required.
	Email string
	// APIToken is the Atlassian API token paired with Email. Required.
	APIToken string
	// Timeout is the per-request HTTP call timeout. Defaults to 15s
	// when zero, matching AIGWCF_JIRA_TIMEOUT_SECONDS.
	Timeout time.Duration
	// Breaker, when set, short-circuits fetches after repeated
	// failures.
	Breaker *CircuitBreaker
	// OutboundHeaders, when set, is consulted per-request to derive
	// extra headers (typically W3C traceparent for span propagation).
	OutboundHeaders func(context.Context) http.Header
	// Observer receives metric events. nil means no-op.
	Observer JiraMetrics
	// Logger is the slog logger for structured warnings. nil means a
	// discard logger. The client never emits raw ticket bodies (PII);
	// only key/outcome/lengths are logged.
	Logger *slog.Logger
}

// Default Jira knobs matching AIGWCF_JIRA_* defaults (HANDOFF §6.2).
const defaultJiraTimeout = 15 * time.Second

// JiraClient is a thin Jira Cloud REST wrapper. Safe for concurrent use
// by many goroutines; all shared state is the breaker + the HTTP client
// (both intrinsically thread-safe).
type JiraClient struct {
	httpClient      *http.Client
	baseURL         string
	timeout         time.Duration
	authHeader      string
	breaker         *CircuitBreaker
	outboundHeaders func(context.Context) http.Header
	observer        JiraMetrics
	logger          *slog.Logger
}

// NewJiraClient validates cfg, applies defaults, and returns a ready
// client. Returns an error if required fields are missing (parity with
// the Python constructor's ValueError). cfg is taken by pointer to
// avoid copying the 104-byte config struct; the caller's cfg is not
// mutated because we work on a local copy below.
func NewJiraClient(cfgIn *JiraClientConfig) (*JiraClient, error) {
	if cfgIn == nil {
		return nil, errors.New("JiraClientConfig is required")
	}
	cfg := *cfgIn
	if cfg.HTTPClient == nil {
		return nil, errors.New("JiraClientConfig.HTTPClient is required")
	}
	if cfg.BaseURL == "" {
		return nil, errors.New("JiraClientConfig.BaseURL is required")
	}
	if cfg.Email == "" || cfg.APIToken == "" {
		return nil, errors.New("JiraClientConfig.Email and APIToken are required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = defaultJiraTimeout
	}
	if cfg.Timeout < time.Millisecond {
		return nil, fmt.Errorf("JiraClientConfig.Timeout %v is too short; minimum is 1ms", cfg.Timeout)
	}
	if cfg.Observer == nil {
		cfg.Observer = noopJiraMetrics{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	auth := base64.StdEncoding.EncodeToString([]byte(cfg.Email + ":" + cfg.APIToken))
	return &JiraClient{
		httpClient:      cfg.HTTPClient,
		baseURL:         strings.TrimRight(cfg.BaseURL, "/"),
		timeout:         cfg.Timeout,
		authHeader:      "Basic " + auth,
		breaker:         cfg.Breaker,
		outboundHeaders: cfg.OutboundHeaders,
		observer:        cfg.Observer,
		logger:          cfg.Logger,
	}, nil
}

// BaseURL returns the normalized base URL (no trailing slash). Exposed
// for dispatcher logging and tests.
func (c *JiraClient) BaseURL() string { return c.baseURL }

// FetchIssueWithChangelog GETs the issue plus its full changelog,
// paginating transparently when the first page reports more entries
// than were returned.
//
// The returned map mirrors the shape Jira emits for `GET /issue/{id}`:
// it includes "id", "key", "self", "fields", "changelog". Only the
// changelog is merged; the rest of the fields are passed through.
//
// Returns *JiraClientError when the breaker is open, the HTTP call
// fails, the response is non-2xx, or decoding fails. Pagination
// errors on subsequent pages are logged and the partial result is
// returned (parity with Python which logs and break s out of the
// paging loop on error).
func (c *JiraClient) FetchIssueWithChangelog(ctx context.Context, issueKey string) (map[string]any, error) {
	if issueKey == "" {
		return nil, &JiraClientError{Outcome: "bad_request", Err: errors.New("empty issueKey")}
	}

	if c.breaker != nil && !c.breaker.Allow() {
		c.observer.RecordCall(string(jiraOutcomeCircuitOpen), "fetch_issue")
		return nil, &JiraClientError{
			Outcome:  string(jiraOutcomeCircuitOpen),
			IssueKey: issueKey,
			Err:      errors.New("jira circuit open; refusing to forward"),
		}
	}

	start := time.Now()
	reqURL := c.baseURL + "/rest/api/3/issue/" + url.PathEscape(issueKey)
	params := url.Values{"expand": []string{"changelog,names,renderedFields"}}
	reqURL += "?" + params.Encode()

	issue, err := c.doJSONGET(ctx, reqURL, "fetch_issue", issueKey)
	c.observer.ObserveCallDuration(time.Since(start), "fetch_issue")
	if err != nil {
		return nil, err
	}

	changelog, _ := issue["changelog"].(map[string]any)
	if needsMoreChangelogPages(changelog) {
		merged, pageErr := c.fetchFullChangelog(ctx, issueKey, changelog)
		if pageErr != nil {
			// Parity: pagination errors are logged and the partial
			// changelog is returned (do not fail the whole fetch).
			c.logger.WarnContext(ctx,
				"jira changelog pagination failed; returning partial",
				slog.String("issue_key", issueKey),
				slog.Any("err", logsafe.Redact(pageErr.Error())),
			)
		} else {
			issue["changelog"] = merged
		}
	}
	return issue, nil
}

// doJSONGET performs a single GET with breaker + metrics integration.
// Parity: mirrors the inner try/except in app/jira_client.py. A non-2xx
// response, network error, or JSON decode error all trip the breaker.
// A circuit-open short-circuit is handled by the caller (we're past
// admission here).
func (c *JiraClient) doJSONGET(ctx context.Context, reqURL, op, issueKey string) (map[string]any, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, reqErr := http.NewRequestWithContext(callCtx, http.MethodGet, reqURL, nil)
	if reqErr != nil {
		return nil, c.recordFailure(op, issueKey, jiraOutcomeHTTPError, reqErr)
	}
	req.Header.Set("Authorization", c.authHeader)
	req.Header.Set("Accept", "application/json")
	if c.outboundHeaders != nil {
		for k, vs := range c.outboundHeaders(ctx) {
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}

	resp, doErr := c.httpClient.Do(req)
	if doErr != nil {
		outcome := jiraOutcomeNetworkError
		switch {
		case errors.Is(doErr, context.Canceled):
			// Caller-side cancellation is neutral per §4.11 — do
			// not record as a breaker failure.
			return nil, doErr
		case errors.Is(doErr, context.DeadlineExceeded):
			outcome = jiraOutcomeTimeout
		}
		return nil, c.recordFailure(op, issueKey, outcome, doErr)
	}
	defer func() { _, _ = io.Copy(io.Discard, resp.Body); _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		httpErr := fmt.Errorf("jira HTTP %d", resp.StatusCode)
		return nil, c.recordFailure(op, issueKey, jiraOutcomeHTTPError, httpErr)
	}

	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return nil, c.recordFailure(op, issueKey, jiraOutcomeHTTPError, readErr)
	}
	var parsed map[string]any
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, c.recordFailure(op, issueKey, jiraOutcomeDecodeError, err)
	}

	if c.breaker != nil {
		c.breaker.RecordSuccess()
	}
	c.observer.RecordCall(string(jiraOutcomeOK), op)
	return parsed, nil
}

// recordFailure centralizes breaker + metrics bookkeeping when a Jira
// call fails for a non-cancellation reason, then wraps the cause in a
// *JiraClientError so callers can errors.As it.
func (c *JiraClient) recordFailure(op, issueKey string, outcome jiraOutcome, cause error) error {
	if c.breaker != nil {
		c.breaker.RecordFailure()
	}
	c.observer.RecordCall(string(outcome), op)
	c.logger.WarnContext(context.Background(),
		"jira call failed",
		slog.String("op", op),
		slog.String("issue_key", issueKey),
		slog.String("outcome", string(outcome)),
		slog.Any("err", logsafe.Redact(cause.Error())),
	)
	return &JiraClientError{Outcome: string(outcome), IssueKey: issueKey, Err: cause}
}

// fetchFullChangelog walks the changelog pagination cursor until every
// history entry is in hand, or until a page errors (in which case the
// caller decides whether to ignore and keep the partial).
//
// Parity: mirrors app/jira_client.py:_fetch_full_changelog. The key
// subtlety is that Jira's secondary endpoint returns "values" while
// the primary issue.changelog returns "histories"; both are tolerated.
func (c *JiraClient) fetchFullChangelog(ctx context.Context, issueKey string, initial map[string]any) (map[string]any, error) {
	histories := coerceSlice(initial["histories"])
	startAt := coerceInt(initial["startAt"], 0)
	maxResults := coerceInt(initial["maxResults"], len(histories))
	if maxResults == 0 {
		maxResults = 100
	}
	total := coerceInt(initial["total"], len(histories))

	for startAt+maxResults < total {
		startAt += maxResults
		reqURL := c.baseURL + "/rest/api/3/issue/" + url.PathEscape(issueKey) + "/changelog"
		q := url.Values{
			"startAt":    []string{strconv.Itoa(startAt)},
			"maxResults": []string{strconv.Itoa(maxResults)},
		}
		reqURL += "?" + q.Encode()

		pageStart := time.Now()
		page, err := c.doJSONGET(ctx, reqURL, "changelog_page", issueKey)
		c.observer.ObserveCallDuration(time.Since(pageStart), "changelog_page")
		if err != nil {
			// Partial return with the error — caller decides.
			return map[string]any{
				"startAt":    0,
				"maxResults": len(histories),
				"total":      len(histories),
				"histories":  histories,
			}, err
		}

		values := coerceSlice(page["values"])
		if len(values) == 0 {
			values = coerceSlice(page["histories"])
		}
		if len(values) == 0 {
			break
		}
		histories = append(histories, values...)
		total = coerceInt(page["total"], total)
		maxResults = coerceInt(page["maxResults"], maxResults)
		if len(values) < maxResults {
			break
		}
	}

	return map[string]any{
		"startAt":    0,
		"maxResults": len(histories),
		"total":      len(histories),
		"histories":  histories,
	}, nil
}

// needsMoreChangelogPages is the pagination-cursor predicate lifted
// verbatim from app/jira_client.py:_needs_more_changelog_pages.
func needsMoreChangelogPages(changelog map[string]any) bool {
	if changelog == nil {
		return false
	}
	histories, ok := changelog["histories"].([]any)
	if !ok {
		return false
	}
	startAt := coerceInt(changelog["startAt"], 0)
	maxResults := coerceInt(changelog["maxResults"], len(histories))
	total := coerceInt(changelog["total"], len(histories))
	return startAt+maxResults < total
}

// ReconstructT0 builds a T0 ticket envelope from an issue + changelog.
//
// The output mirrors the Jira `GET /issue/{id}` shape so downstream
// tools keep working. Any field outside T0FieldWhitelist is dropped.
//
// Algorithm: sort histories by `created` descending, walk them in that
// order (newest → oldest). For each whitelisted change, overwrite the
// "current" field value with `fromString` (or `from` when `fromString`
// is missing). After walking all histories the accumulated values are
// filtered to the whitelist and emitted.
//
// Parity: a line-for-line port of app/jira_client.py:reconstruct_t0.
// The sort-by-created-descending is semantically identical to Python's
// stable sort; ties between items sharing a timestamp retain input
// order.
func ReconstructT0(issue map[string]any) map[string]any {
	fields := map[string]any{}
	if f, ok := issue["fields"].(map[string]any); ok {
		for k, v := range f {
			fields[k] = v
		}
	}

	changelog, _ := issue["changelog"].(map[string]any)
	histories := coerceSlice(changelog["histories"])

	// Sort histories by "created" descending. Missing `created`
	// sorts last; this matches Python's `key=lambda h: h.get("created", "")`
	// with `reverse=True` (missing keys compare as "" which is the
	// smallest string).
	sort.SliceStable(histories, func(i, j int) bool {
		return getString(histories[i], "created") > getString(histories[j], "created")
	})

	for _, h := range histories {
		history, ok := h.(map[string]any)
		if !ok {
			continue
		}
		items := coerceSlice(history["items"])
		for _, it := range items {
			item, ok := it.(map[string]any)
			if !ok {
				continue
			}
			fieldName, _ := item["field"].(string)
			if fieldName == "" {
				continue
			}
			if _, allowed := T0FieldWhitelist[fieldName]; !allowed {
				continue
			}
			// Prefer fromString; fall back to `from`. Python uses
			// `if from_str is None: from_str = item.get("from")`,
			// where "None" means key absent or explicit null.
			value := item["fromString"]
			if value == nil {
				value = item["from"]
			}
			fields[fieldName] = value
		}
	}

	// Filter the accumulated fields to the whitelist.
	t0Fields := make(map[string]any, len(fields))
	for k, v := range fields {
		if _, allowed := T0FieldWhitelist[k]; allowed {
			t0Fields[k] = v
		}
	}

	return map[string]any{
		"id":               issue["id"],
		"key":              issue["key"],
		"self":             issue["self"],
		"fields":           t0Fields,
		"t0_reconstructed": true,
	}
}

// RewriteJQLExcluding appends `AND key != "<ticket>"` to an existing
// JQL string. Idempotent: if the exclusion is already present the
// query is returned unchanged. Handles the case where the user's JQL
// is empty (returns the exclusion standalone).
//
// Parity: mirrors app/jira_client.py:rewrite_jql_excluding exactly,
// including the parenthesization of the original JQL to guarantee
// associativity regardless of operator precedence in the input.
func RewriteJQLExcluding(jql, ticketKey string) string {
	exclusion := `key != "` + ticketKey + `"`
	trimmed := strings.TrimSpace(jql)
	if trimmed == "" {
		return exclusion
	}
	if strings.Contains(jql, exclusion) {
		return jql
	}
	return "(" + jql + ") AND " + exclusion
}

// coerceSlice normalizes a JSON-decoded value into a []any. json.Unmarshal
// into map[string]any produces []any for arrays; this helper tolerates
// nil / missing keys by returning an empty slice so call-site loops stay
// short.
func coerceSlice(v any) []any {
	if v == nil {
		return nil
	}
	if s, ok := v.([]any); ok {
		return s
	}
	return nil
}

// coerceInt accepts the shapes json.Unmarshal may return for a numeric
// field: float64 (default), int (when callers pre-cast), and nil
// (missing key). A fallback is used when the value is absent or the
// type is unexpected.
func coerceInt(v any, fallback int) int {
	switch x := v.(type) {
	case nil:
		return fallback
	case int:
		return x
	case int64:
		return int(x)
	case float64:
		return int(x)
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return int(i)
		}
		return fallback
	default:
		return fallback
	}
}

// getString extracts a string field from a map[string]any, tolerating
// any input shape (non-map, missing key, non-string value).
func getString(v any, key string) string {
	m, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	s, _ := m[key].(string)
	return s
}
