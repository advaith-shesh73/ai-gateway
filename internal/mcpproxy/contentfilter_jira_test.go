// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

// Jira client / T0 / JQL parity tests.
//
// Test names are a direct port of tests/test_jira_client.py so auditors
// can pattern-match 1:1 between Python and Go when verifying the
// port. Each Python TestCase class becomes a Test* prefix group below.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// -----------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------

// quietJiraLogger discards all logs — we don't want test output
// polluted by intentional warn lines from recordFailure().
func quietJiraLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newJiraTestServer starts a test HTTP server that routes every
// incoming request through `handler` and returns the server plus its
// base URL. Caller is responsible for closing.
func newJiraTestServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// newJiraClientForTest builds a JiraClient with test defaults and
// applies optional overrides. Mirrors `_make_client` in the Python
// test file.
func newJiraClientForTest(t *testing.T, baseURL string, override func(*JiraClientConfig)) *JiraClient {
	t.Helper()
	cfg := JiraClientConfig{
		HTTPClient: &http.Client{Timeout: 5 * time.Second},
		BaseURL:    baseURL,
		Email:      "bot@example.com",
		APIToken:   "token123",
		Timeout:    5 * time.Second,
		Logger:     quietJiraLogger(),
	}
	if override != nil {
		override(&cfg)
	}
	c, err := NewJiraClient(&cfg)
	if err != nil {
		t.Fatalf("NewJiraClient: %v", err)
	}
	return c
}

// requireJiraError asserts err is a *JiraClientError and optionally
// matches the provided substring against Error().
func requireJiraError(t *testing.T, err error, contains string) *JiraClientError {
	t.Helper()
	if err == nil {
		t.Fatalf("expected *JiraClientError, got nil")
	}
	var je *JiraClientError
	if !errors.As(err, &je) {
		t.Fatalf("expected *JiraClientError, got %T: %v", err, err)
	}
	if contains != "" && !strings.Contains(je.Error(), contains) {
		t.Fatalf("expected error to contain %q, got %q", contains, je.Error())
	}
	return je
}

// -----------------------------------------------------------------------
// TestJiraClientInit — constructor validation parity
// -----------------------------------------------------------------------

func TestJiraClientInit_RequiresBaseURL(t *testing.T) {
	_, err := NewJiraClient(&JiraClientConfig{
		HTTPClient: &http.Client{},
		BaseURL:    "",
		Email:      "e@e.com",
		APIToken:   "t",
		Timeout:    5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "BaseURL") {
		t.Fatalf("want BaseURL error, got %v", err)
	}
}

func TestJiraClientInit_RequiresEmailAndToken(t *testing.T) {
	_, err := NewJiraClient(&JiraClientConfig{
		HTTPClient: &http.Client{},
		BaseURL:    "https://j.example",
		Email:      "",
		APIToken:   "t",
		Timeout:    5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "Email and APIToken") {
		t.Fatalf("want Email+APIToken error, got %v", err)
	}
	_, err = NewJiraClient(&JiraClientConfig{
		HTTPClient: &http.Client{},
		BaseURL:    "https://j.example",
		Email:      "e@e.com",
		APIToken:   "",
		Timeout:    5 * time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "Email and APIToken") {
		t.Fatalf("want Email+APIToken error, got %v", err)
	}
}

func TestJiraClientInit_StripsTrailingSlash(t *testing.T) {
	c := newJiraClientForTest(t, "https://jira.example.com/", nil)
	if got, want := c.BaseURL(), "https://jira.example.com"; got != want {
		t.Fatalf("baseURL=%q, want %q", got, want)
	}
}

func TestJiraClientInit_BuildsBasicAuthHeader(t *testing.T) {
	c := newJiraClientForTest(t, "https://jira.example.com", func(cfg *JiraClientConfig) {
		cfg.Email = "alice@example.com"
		cfg.APIToken = "secret"
	})
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice@example.com:secret"))
	if c.authHeader != want {
		t.Fatalf("authHeader=%q, want %q", c.authHeader, want)
	}
}

// -----------------------------------------------------------------------
// TestFetchIssueWithChangelog — HTTP path parity
// -----------------------------------------------------------------------

func TestFetchIssue_BasicFetch(t *testing.T) {
	var captured []string
	var capturedAuth string
	srv := newJiraTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		captured = append(captured, r.URL.String())
		capturedAuth = r.Header.Get("Authorization")
		_, _ = io.WriteString(w, `{
			"id": "10001",
			"key": "ENG-1",
			"fields": {"summary": "S"},
			"changelog": {"histories": [], "total": 0, "startAt": 0, "maxResults": 100}
		}`)
	})
	client := newJiraClientForTest(t, srv.URL, nil)
	issue, err := client.FetchIssueWithChangelog(context.Background(), "ENG-1")
	if err != nil {
		t.Fatalf("FetchIssueWithChangelog: %v", err)
	}
	if got := issue["key"]; got != "ENG-1" {
		t.Fatalf("key=%v, want ENG-1", got)
	}
	fields, _ := issue["fields"].(map[string]any)
	if got := fields["summary"]; got != "S" {
		t.Fatalf("summary=%v, want S", got)
	}
	if len(captured) != 1 {
		t.Fatalf("want 1 request, got %d", len(captured))
	}
	// Python test asserts the URL ends in `?expand=changelog%2Cnames%2CrenderedFields`
	// — we assert the same via url.Values parsing since Go's PathEscape may
	// reorder query params.
	parsed, _ := url.Parse(srv.URL + captured[0])
	if got, want := parsed.Path, "/rest/api/3/issue/ENG-1"; got != want {
		t.Fatalf("path=%q, want %q", got, want)
	}
	if got, want := parsed.Query().Get("expand"), "changelog,names,renderedFields"; got != want {
		t.Fatalf("expand=%q, want %q", got, want)
	}
	if !strings.HasPrefix(capturedAuth, "Basic ") {
		t.Fatalf("authorization header=%q, want Basic prefix", capturedAuth)
	}
}

func TestFetchIssue_HTTPErrorRaisesJiraClientError(t *testing.T) {
	srv := newJiraTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	client := newJiraClientForTest(t, srv.URL, nil)
	_, err := client.FetchIssueWithChangelog(context.Background(), "ENG-1")
	je := requireJiraError(t, err, "ENG-1")
	if je.Outcome != string(jiraOutcomeHTTPError) {
		t.Fatalf("outcome=%q, want http_error", je.Outcome)
	}
}

func TestFetchIssue_NetworkErrorRaisesJiraClientError(t *testing.T) {
	// Build a client pointing to a closed listener so Dial fails
	// immediately. This is a Go-native shape for httpx.ConnectError.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close() // dial will now refuse

	client := newJiraClientForTest(t, "http://"+addr, nil)
	_, fetchErr := client.FetchIssueWithChangelog(context.Background(), "ENG-1")
	je := requireJiraError(t, fetchErr, "ENG-1")
	// Either network_error or timeout is acceptable depending on
	// the kernel's ECONNREFUSED vs. stall behavior; the important
	// invariant is that it's classified as a failure, not OK.
	if je.Outcome != string(jiraOutcomeNetworkError) && je.Outcome != string(jiraOutcomeTimeout) {
		t.Fatalf("outcome=%q, want network_error or timeout", je.Outcome)
	}
}

func TestFetchIssue_PaginationMergesPages(t *testing.T) {
	var mu sync.Mutex
	var pageCalls []string
	srv := newJiraTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pageCalls = append(pageCalls, r.URL.String())
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/ENG-1") {
			_, _ = io.WriteString(w, `{
				"id": "10001",
				"key": "ENG-1",
				"fields": {"summary": "S"},
				"changelog": {
					"histories": [{"id":"1"},{"id":"2"}],
					"total": 5,
					"startAt": 0,
					"maxResults": 2
				}
			}`)
			return
		}
		startAt, _ := strconv.Atoi(r.URL.Query().Get("startAt"))
		switch startAt {
		case 2:
			_, _ = io.WriteString(w, `{
				"values": [{"id":"3"},{"id":"4"}],
				"total": 5, "startAt": 2, "maxResults": 2
			}`)
		case 4:
			_, _ = io.WriteString(w, `{
				"values": [{"id":"5"}],
				"total": 5, "startAt": 4, "maxResults": 2
			}`)
		default:
			_, _ = io.WriteString(w, `{"values": []}`)
		}
	})

	client := newJiraClientForTest(t, srv.URL, nil)
	issue, err := client.FetchIssueWithChangelog(context.Background(), "ENG-1")
	if err != nil {
		t.Fatalf("FetchIssueWithChangelog: %v", err)
	}
	cl, _ := issue["changelog"].(map[string]any)
	histories := coerceSlice(cl["histories"])
	ids := make([]string, 0, len(histories))
	for _, h := range histories {
		m, _ := h.(map[string]any)
		ids = append(ids, fmt.Sprint(m["id"]))
	}
	if want := []string{"1", "2", "3", "4", "5"}; !stringSlicesEqual(ids, want) {
		t.Fatalf("ids=%v, want %v", ids, want)
	}
}

func TestFetchIssue_PaginationStopsOnError(t *testing.T) {
	srv := newJiraTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/ENG-1") {
			_, _ = io.WriteString(w, `{
				"id": "10001",
				"key": "ENG-1",
				"fields": {},
				"changelog": {
					"histories": [{"id":"1"}],
					"total": 5,
					"startAt": 0,
					"maxResults": 1
				}
			}`)
			return
		}
		http.Error(w, "boom", http.StatusInternalServerError)
	})
	client := newJiraClientForTest(t, srv.URL, nil)
	issue, err := client.FetchIssueWithChangelog(context.Background(), "ENG-1")
	if err != nil {
		t.Fatalf("partial-on-error must not raise: %v", err)
	}
	cl, _ := issue["changelog"].(map[string]any)
	histories := coerceSlice(cl["histories"])
	if got, want := len(histories), 1; got != want {
		t.Fatalf("history count=%d, want %d", got, want)
	}
}

// Extra Go-only test: verify caller context cancellation is neutral
// (does not trip the breaker). Parity intent: §4.11 / §7.7.5.
func TestFetchIssue_ContextCancellationIsNeutralForBreaker(t *testing.T) {
	srv := newJiraTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(500 * time.Millisecond):
			_, _ = io.WriteString(w, `{"id":"1","key":"ENG-1","fields":{}}`)
		case <-r.Context().Done():
			return
		}
	})
	br := NewCircuitBreakerWithClock("jira",
		CircuitBreakerConfig{FailureThreshold: 2, ResetTimeout: 30 * time.Second},
		func() time.Time { return time.Unix(0, 0) },
		quietJiraLogger(), nil)
	client := newJiraClientForTest(t, srv.URL, func(cfg *JiraClientConfig) {
		cfg.Breaker = br
	})
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	_, err := client.FetchIssueWithChangelog(ctx, "ENG-1")
	if err == nil {
		t.Fatalf("expected cancellation-related error, got nil")
	}
	if br.State() != CircuitClosed {
		t.Fatalf("breaker should remain CLOSED on caller cancel; state=%v", br.State())
	}
}

// Extra Go-only: prove that breaker short-circuits before any HTTP
// request is made when circuit is OPEN.
func TestFetchIssue_OpenCircuitShortCircuits(t *testing.T) {
	var hit atomic.Int32
	srv := newJiraTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = io.WriteString(w, `{}`)
	})
	br := NewCircuitBreakerWithClock("jira",
		CircuitBreakerConfig{FailureThreshold: 1, ResetTimeout: 30 * time.Second},
		func() time.Time { return time.Unix(0, 0) },
		quietJiraLogger(), nil)
	// Force breaker to OPEN.
	br.RecordFailure()
	if br.State() != CircuitOpen {
		t.Fatalf("test setup: breaker should be OPEN, got %v", br.State())
	}

	client := newJiraClientForTest(t, srv.URL, func(cfg *JiraClientConfig) {
		cfg.Breaker = br
	})
	_, err := client.FetchIssueWithChangelog(context.Background(), "ENG-1")
	je := requireJiraError(t, err, "ENG-1")
	if je.Outcome != string(jiraOutcomeCircuitOpen) {
		t.Fatalf("outcome=%q, want circuit_open", je.Outcome)
	}
	if hit.Load() != 0 {
		t.Fatalf("HTTP server was hit %d times; should be 0", hit.Load())
	}
}

// -----------------------------------------------------------------------
// TestReconstructT0 — T0 replay parity
// -----------------------------------------------------------------------

func TestReconstructT0_PassthroughWhenNoChangelog(t *testing.T) {
	issue := map[string]any{
		"id":  "10001",
		"key": "ENG-1",
		"fields": map[string]any{
			"summary":     "Current summary",
			"description": "desc",
		},
	}
	t0 := ReconstructT0(issue)
	if got := t0["key"]; got != "ENG-1" {
		t.Fatalf("key=%v, want ENG-1", got)
	}
	fields, _ := t0["fields"].(map[string]any)
	if got, want := fields["summary"], "Current summary"; got != want {
		t.Fatalf("summary=%v, want %v", got, want)
	}
	if got, want := fields["description"], "desc"; got != want {
		t.Fatalf("description=%v, want %v", got, want)
	}
	if t0["t0_reconstructed"] != true {
		t.Fatalf("t0_reconstructed must be true")
	}
}

func TestReconstructT0_ReplaysChangelogInReverse(t *testing.T) {
	issue := map[string]any{
		"id":  "10001",
		"key": "ENG-1",
		"fields": map[string]any{
			"summary":     "v3",
			"description": "body-v3",
		},
		"changelog": map[string]any{
			"histories": []any{
				map[string]any{
					"created": "2025-01-01T00:00:00Z",
					"items": []any{
						map[string]any{"field": "summary", "fromString": "v1", "toString": "v2"},
					},
				},
				map[string]any{
					"created": "2025-02-01T00:00:00Z",
					"items": []any{
						map[string]any{"field": "summary", "fromString": "v2", "toString": "v3"},
						map[string]any{"field": "description", "fromString": "body-v1", "toString": "body-v3"},
					},
				},
			},
		},
	}
	t0 := ReconstructT0(issue)
	fields, _ := t0["fields"].(map[string]any)
	if got, want := fields["summary"], "v1"; got != want {
		t.Fatalf("summary=%v, want %v", got, want)
	}
	if got, want := fields["description"], "body-v1"; got != want {
		t.Fatalf("description=%v, want %v", got, want)
	}
}

func TestReconstructT0_DropsNonWhitelistedFields(t *testing.T) {
	issue := map[string]any{
		"id":  "1",
		"key": "ENG-1",
		"fields": map[string]any{
			"summary":    "keep",
			"status":     map[string]any{"name": "In Progress"},
			"resolution": "Fixed",
			"comment":    map[string]any{"comments": []any{map[string]any{"body": "hi"}}},
		},
	}
	t0 := ReconstructT0(issue)
	fields, _ := t0["fields"].(map[string]any)
	for _, forbid := range []string{"status", "resolution", "comment"} {
		if _, exists := fields[forbid]; exists {
			t.Fatalf("field %q must be dropped", forbid)
		}
	}
	if got, want := fields["summary"], "keep"; got != want {
		t.Fatalf("summary=%v, want %v", got, want)
	}
}

func TestReconstructT0_IgnoresNonWhitelistedChangelogChanges(t *testing.T) {
	issue := map[string]any{
		"id":  "1",
		"key": "ENG-1",
		"fields": map[string]any{
			"summary": "current",
		},
		"changelog": map[string]any{
			"histories": []any{
				map[string]any{
					"created": "2025-01-01T00:00:00Z",
					"items": []any{
						map[string]any{"field": "status", "fromString": "Open", "toString": "Closed"},
					},
				},
			},
		},
	}
	t0 := ReconstructT0(issue)
	fields, _ := t0["fields"].(map[string]any)
	if got, want := len(fields), 1; got != want {
		t.Fatalf("field count=%d, want %d", got, want)
	}
	if got, want := fields["summary"], "current"; got != want {
		t.Fatalf("summary=%v, want %v", got, want)
	}
}

func TestReconstructT0_HandlesMissingItems(t *testing.T) {
	issue := map[string]any{
		"id":  "1",
		"key": "ENG-1",
		"fields": map[string]any{
			"summary": "hi",
		},
		"changelog": map[string]any{
			"histories": []any{
				map[string]any{"created": "2025-01-01T00:00:00Z"},
			},
		},
	}
	t0 := ReconstructT0(issue)
	fields, _ := t0["fields"].(map[string]any)
	if got, want := fields["summary"], "hi"; got != want {
		t.Fatalf("summary=%v, want %v", got, want)
	}
}

func TestReconstructT0_PreservesIdentifiers(t *testing.T) {
	issue := map[string]any{
		"id":     "42",
		"key":    "ENG-42",
		"self":   "https://j/rest/api/3/issue/42",
		"fields": map[string]any{},
	}
	t0 := ReconstructT0(issue)
	if got := t0["id"]; got != "42" {
		t.Fatalf("id=%v, want 42", got)
	}
	if got := t0["key"]; got != "ENG-42" {
		t.Fatalf("key=%v, want ENG-42", got)
	}
	if got := t0["self"]; got != "https://j/rest/api/3/issue/42" {
		t.Fatalf("self=%v", got)
	}
}

func TestReconstructT0_WhitelistCoversCreationTimeFields(t *testing.T) {
	required := []string{"summary", "description", "reporter", "created", "issuetype", "project"}
	for _, k := range required {
		if _, ok := T0FieldWhitelist[k]; !ok {
			t.Fatalf("whitelist missing required field %q", k)
		}
	}
}

func TestReconstructT0_WhitelistExcludesPostCreationFields(t *testing.T) {
	forbidden := []string{"status", "resolution", "comment", "worklog", "fixVersions"}
	for _, k := range forbidden {
		if _, ok := T0FieldWhitelist[k]; ok {
			t.Fatalf("whitelist must not contain post-creation field %q", k)
		}
	}
}

func TestReconstructT0_EmptyIssue(t *testing.T) {
	t0 := ReconstructT0(map[string]any{})
	fields, _ := t0["fields"].(map[string]any)
	if got, want := len(fields), 0; got != want {
		t.Fatalf("field count=%d, want %d", got, want)
	}
	if t0["t0_reconstructed"] != true {
		t.Fatalf("t0_reconstructed must be true for empty issue")
	}
}

// Extra Go-only: when `fromString` is absent but `from` exists we fall
// back to `from`. This is important for Jira fields whose changelog
// entries omit the rendered string and only emit the ID (the Python
// test file exercises this implicitly via integration fixtures; we
// make it explicit in Go).
func TestReconstructT0_FallsBackToFromWhenFromStringMissing(t *testing.T) {
	issue := map[string]any{
		"id":  "1",
		"key": "ENG-1",
		"fields": map[string]any{
			"priority": map[string]any{"id": "3", "name": "Medium"},
		},
		"changelog": map[string]any{
			"histories": []any{
				map[string]any{
					"created": "2025-01-01T00:00:00Z",
					"items": []any{
						map[string]any{"field": "priority", "from": "1", "toString": "Medium"},
					},
				},
			},
		},
	}
	t0 := ReconstructT0(issue)
	fields, _ := t0["fields"].(map[string]any)
	if got, want := fields["priority"], "1"; got != want {
		t.Fatalf("priority=%v, want %v", got, want)
	}
}

// -----------------------------------------------------------------------
// TestRewriteJqlExcluding — parity with Python JQL rewriter
// -----------------------------------------------------------------------

func TestRewriteJQL_EmptyJQLUsesExclusionOnly(t *testing.T) {
	if got, want := RewriteJQLExcluding("", "ENG-1"), `key != "ENG-1"`; got != want {
		t.Fatalf("empty jql: got %q, want %q", got, want)
	}
	if got, want := RewriteJQLExcluding("   ", "ENG-1"), `key != "ENG-1"`; got != want {
		t.Fatalf("whitespace jql: got %q, want %q", got, want)
	}
}

func TestRewriteJQL_AppendsExclusionToExistingJQL(t *testing.T) {
	got := RewriteJQLExcluding("project = ENG", "ENG-1")
	want := `(project = ENG) AND key != "ENG-1"`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRewriteJQL_IdempotentWhenAlreadyPresent(t *testing.T) {
	jql := `(project = ENG) AND key != "ENG-1"`
	if got := RewriteJQLExcluding(jql, "ENG-1"); got != jql {
		t.Fatalf("got %q, want unchanged %q", got, jql)
	}
}

func TestRewriteJQL_DifferentTicketIDsAreAppended(t *testing.T) {
	jql := `(project = ENG) AND key != "ENG-1"`
	out := RewriteJQLExcluding(jql, "ENG-2")
	if !strings.Contains(out, `key != "ENG-2"`) {
		t.Fatalf("missing new exclusion: %q", out)
	}
	if !strings.Contains(out, `key != "ENG-1"`) {
		t.Fatalf("missing original exclusion: %q", out)
	}
}

// -----------------------------------------------------------------------
// JSON decode helpers — parity with Python dict traversal on mixed types
// -----------------------------------------------------------------------

func TestCoerceInt_AcceptsFloat64(t *testing.T) {
	if got := coerceInt(float64(42), -1); got != 42 {
		t.Fatalf("got %d, want 42", got)
	}
}

func TestCoerceInt_AcceptsJSONNumber(t *testing.T) {
	var payload map[string]any
	decoder := json.NewDecoder(strings.NewReader(`{"n":7}`))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := coerceInt(payload["n"], -1); got != 7 {
		t.Fatalf("got %d, want 7", got)
	}
}

func TestCoerceInt_FallbackOnMissingOrBadType(t *testing.T) {
	if got := coerceInt(nil, 99); got != 99 {
		t.Fatalf("got %d, want 99", got)
	}
	if got := coerceInt("not-a-number", 99); got != 99 {
		t.Fatalf("got %d, want 99", got)
	}
}

// Small helper to compare slices of strings so tests don't depend on
// reflect.DeepEqual's zero-value oddities for empty slices.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
