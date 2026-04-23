// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/filterapi"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// makeID is a convenience that panics on error since tests construct IDs
// from primitive int literals.
func makeID(t *testing.T, v any) jsonrpc.ID {
	t.Helper()
	id, err := jsonrpc.MakeID(v)
	require.NoError(t, err)
	return id
}

// --- compileContentFilter --------------------------------------------------

func TestCompileContentFilter_Nil(t *testing.T) {
	cf, err := compileContentFilter(nil, "r", "b")
	require.NoError(t, err)
	require.Nil(t, cf)
}

func TestCompileContentFilter_RejectsEmptyURL(t *testing.T) {
	_, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:    "",
		Scopes: []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
	}, "r", "b")
	require.Error(t, err)
	require.Contains(t, err.Error(), "url is required")
}

func TestCompileContentFilter_RejectsBadURLScheme(t *testing.T) {
	cases := []string{"", "ftp://host", "mailto:x@y", "file:///tmp/x", "ws://host"}
	for _, u := range cases {
		t.Run(u, func(t *testing.T) {
			_, err := compileContentFilter(&filterapi.MCPContentFilter{
				URL:    u,
				Scopes: []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
			}, "r", "b")
			require.Error(t, err)
		})
	}
}

func TestCompileContentFilter_RejectsNoScopes(t *testing.T) {
	_, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL: "http://x",
	}, "r", "b")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at least one scope")
}

func TestCompileContentFilter_UnknownScope(t *testing.T) {
	_, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:    "http://x",
		Scopes: []filterapi.MCPContentFilterScope{"not-a-scope"},
	}, "r", "b")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown scope")
}

func TestCompileContentFilter_UnknownFailurePolicy(t *testing.T) {
	_, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:           "http://x",
		Scopes:        []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		FailurePolicy: "weird",
	}, "r", "b")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown failure policy")
}

func TestCompileContentFilter_DefaultsAndCanonicalization(t *testing.T) {
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL: "https://filter.example.com",
		Scopes: []filterapi.MCPContentFilterScope{
			filterapi.MCPContentFilterScopeRequest,
			filterapi.MCPContentFilterScopeResponse,
		},
		// unset TimeoutSeconds -> default
		// empty FailurePolicy -> PassThrough (fail-open)
		ForwardHeaders: []string{
			"x-request-id",
			"X-Request-Id",  // duplicate after canonicalization
			"  x-user-id  ", // whitespace trimmed
			"",              // empty after trim - skipped
		},
	}, "route1", "backend1")
	require.NoError(t, err)
	require.NotNil(t, cf)
	require.Equal(t, "https://filter.example.com", cf.url)
	require.True(t, cf.invokeOnRequest)
	require.True(t, cf.invokeOnResponse)
	require.Equal(t, contentFilterDefaultTimeout, cf.timeout)
	require.False(t, cf.failClosed)
	require.ElementsMatch(t, []string{"X-Request-Id", "X-User-Id"}, cf.forwardHeadersCanonical)
}

func TestCompileContentFilter_CustomTimeoutAndFailPolicy(t *testing.T) {
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:            "http://x",
		Scopes:         []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		TimeoutSeconds: 30,
		FailurePolicy:  filterapi.MCPContentFilterFailurePolicyFail,
	}, "r", "b")
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, cf.timeout)
	require.True(t, cf.failClosed)
}

// --- Policies compile ------------------------------------------------------

// TestCompileContentFilter_PoliciesEmptyYieldsNil asserts that neither
// a missing nor an empty Policies slice allocates anything — the
// envelope path substitutes []string{} at send time, but the compiled
// filter stores nil. This keeps the "no policies attached" snapshot
// cheap and lets the envelope code stay the single place that decides
// the wire shape.
func TestCompileContentFilter_PoliciesEmptyYieldsNil(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		cf, err := compileContentFilter(&filterapi.MCPContentFilter{
			URL:    "http://x",
			Scopes: []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		}, "r", "b")
		require.NoError(t, err)
		require.Nil(t, cf.policies)
	})
	t.Run("empty_slice", func(t *testing.T) {
		cf, err := compileContentFilter(&filterapi.MCPContentFilter{
			URL:      "http://x",
			Scopes:   []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
			Policies: []filterapi.MCPContentFilterPolicy{},
		}, "r", "b")
		require.NoError(t, err)
		require.Nil(t, cf.policies)
	})
}

// TestCompileContentFilter_PoliciesPreservedAndDeduped asserts the
// compile step preserves author-declared order while dropping duplicate
// and whitespace-only entries. Order matters because the filter service
// merges verdicts with a well-defined precedence; reordering would
// change observability output (trace attribute order, audit log).
func TestCompileContentFilter_PoliciesPreservedAndDeduped(t *testing.T) {
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:    "http://x",
		Scopes: []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		Policies: []filterapi.MCPContentFilterPolicy{
			filterapi.MCPContentFilterPolicyPII,
			filterapi.MCPContentFilterPolicyEvalPolicy,
			filterapi.MCPContentFilterPolicyPII, // duplicate
			"",                                  // empty, skipped
			"   ",                               // whitespace-only, skipped
			"secrets",                           // forward-compat unknown value accepted verbatim
		},
	}, "r", "b")
	require.NoError(t, err)
	require.Equal(t, []string{"pii", "evalpolicy", "secrets"}, cf.policies)
}

// TestCompileContentFilter_PoliciesAcceptsUnknown asserts the gateway
// does NOT reject unknown policy names at compile time. The CRD's
// Enum validator catches typos at admission, and forward-compat is
// expensive to lose: an operator should be able to enable a new policy
// by editing CRD + filter service without rebuilding the gateway.
func TestCompileContentFilter_PoliciesAcceptsUnknown(t *testing.T) {
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:      "http://x",
		Scopes:   []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		Policies: []filterapi.MCPContentFilterPolicy{"future-policy"},
	}, "r", "b")
	require.NoError(t, err)
	require.Equal(t, []string{"future-policy"}, cf.policies)
}

// --- selectHeaders ---------------------------------------------------------

func TestSelectHeaders_NilSourceReturnsEmpty(t *testing.T) {
	cf := &contentFilter{forwardHeadersCanonical: []string{"X-Foo"}}
	out := cf.selectHeaders(nil)
	require.NotNil(t, out)
	require.Empty(t, out)
}

func TestSelectHeaders_NoForwardList(t *testing.T) {
	cf := &contentFilter{}
	hdr := http.Header{"X-Foo": []string{"bar"}}
	out := cf.selectHeaders(hdr)
	require.Empty(t, out)
}

func TestSelectHeaders_PicksOnlyConfiguredHeaders(t *testing.T) {
	cf := &contentFilter{forwardHeadersCanonical: []string{"X-Request-Id", "X-User-Id"}}
	hdr := http.Header{}
	hdr.Set("x-request-id", "abc")
	hdr.Add("X-User-Id", "u1")
	hdr.Add("X-User-Id", "u2")
	hdr.Set("X-Secret", "should-not-forward")
	out := cf.selectHeaders(hdr)
	require.ElementsMatch(t, []string{"abc"}, out["X-Request-Id"])
	require.ElementsMatch(t, []string{"u1", "u2"}, out["X-User-Id"])
	require.NotContains(t, out, "X-Secret")
}

// --- invoke (HTTP behavior) ------------------------------------------------

// helper: build a minimal filter pointing at the given test server URL
func newTestFilter(t *testing.T, serverURL string, failClosed bool) *contentFilter {
	t.Helper()
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL: serverURL,
		Scopes: []filterapi.MCPContentFilterScope{
			filterapi.MCPContentFilterScopeRequest,
			filterapi.MCPContentFilterScopeResponse,
		},
		TimeoutSeconds: 1,
		FailurePolicy: func() filterapi.MCPContentFilterFailurePolicy {
			if failClosed {
				return filterapi.MCPContentFilterFailurePolicyFail
			}
			return filterapi.MCPContentFilterFailurePolicyPassThrough
		}(),
	}, "r", "b")
	require.NoError(t, err)
	return cf
}

func TestInvoke_PassReturnsOriginalBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	client := &http.Client{}
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	newBody, rejected, reason, err := cf.invoke(context.Background(), client,
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, body)
	require.NoError(t, err)
	require.False(t, rejected)
	require.Empty(t, reason)
	require.Equal(t, body, newBody)
}

// TestInvoke_PoliciesForwardedInEnvelope asserts the compiled policy
// list is serialized on the filter-request wire in the order the
// operator declared and is always an array (never null / missing) so
// filter implementations can rely on a stable schema.
func TestInvoke_PoliciesForwardedInEnvelope(t *testing.T) {
	var got contentFilterRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&got))
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:    srv.URL,
		Scopes: []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		Policies: []filterapi.MCPContentFilterPolicy{
			filterapi.MCPContentFilterPolicyPII,
			filterapi.MCPContentFilterPolicyEvalPolicy,
		},
	}, "r", "b")
	require.NoError(t, err)
	_, _, _, err = cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.NoError(t, err)
	require.Equal(t, []string{"pii", "evalpolicy"}, got.Policies)
}

// TestInvoke_PoliciesEmptyEnvelopeIsArray asserts an unset Policies
// field still produces an empty JSON array on the wire. Filters that
// iterate policies to decide which engines to run must never observe
// JSON null — that would force every filter to special-case nullability.
func TestInvoke_PoliciesEmptyEnvelopeIsArray(t *testing.T) {
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, _, _, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"policies":[]`,
		"empty Policies must serialize as [] to keep a stable wire shape")
}

func TestInvoke_RedactReturnsNewBody(t *testing.T) {
	replacement := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"redacted":true}}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action:     contentFilterActionRedact,
			BodyBase64: base64.StdEncoding.EncodeToString(replacement),
			Reason:     "masked pii",
		})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	client := &http.Client{}
	original := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"email":"a@b.com"}}`)
	newBody, rejected, reason, err := cf.invoke(context.Background(), client,
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, original)
	require.NoError(t, err)
	require.False(t, rejected)
	require.Equal(t, "masked pii", reason)
	require.Equal(t, replacement, newBody)
}

func TestInvoke_RedactMissingBodyIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionRedact})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, true)
	_, _, _, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "missing bodyBase64")
}

func TestInvoke_RejectReturnsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action: contentFilterActionReject,
			Reason: "contains secret",
		})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, rejected, reason, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.NoError(t, err)
	require.True(t, rejected)
	require.Equal(t, "contains secret", reason)
}

func TestInvoke_UnknownActionIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: "gibberish"})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, _, _, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown action")
}

func TestInvoke_NonSuccessStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, _, _, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "HTTP 400")
}

func TestInvoke_MalformedResponseJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, _, _, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "decode content filter response")
}

func TestInvoke_ResponseOverSizeLimit(t *testing.T) {
	big := strings.Repeat("a", contentFilterMaxBodyBytes+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Keep it valid JSON but huge so that io.LimitReader trips.
		_, _ = fmt.Fprintf(w, `{"action":"redact","bodyBase64":"%s"}`, big)
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, _, _, err := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds")
}

func TestInvoke_Timeout(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(2 * time.Second):
			_, _ = io.WriteString(w, `{"action":"pass"}`)
		case <-done:
			return
		}
	}))
	defer func() { close(done); srv.Close() }()
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:            srv.URL,
		Scopes:         []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		TimeoutSeconds: 1, // 1s, server sleeps 2s
	}, "r", "b")
	require.NoError(t, err)
	start := time.Now()
	_, _, _, invokeErr := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "r", "b", "tools/call", "", http.Header{}, []byte(`{}`))
	elapsed := time.Since(start)
	require.Error(t, invokeErr)
	require.Less(t, elapsed, 2*time.Second, "should time out well before server responds")
}

func TestInvoke_SendsConfiguredHeadersOnly(t *testing.T) {
	var seenEnv contentFilterRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&seenEnv))
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:            srv.URL,
		Scopes:         []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		ForwardHeaders: []string{"X-Request-Id", "X-User-Id"},
	}, "r", "b")
	require.NoError(t, err)
	hdr := http.Header{}
	hdr.Set("x-request-id", "abc")
	hdr.Set("X-User-Id", "u1")
	hdr.Set("Authorization", "Bearer s3cr3t")
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`)
	_, _, _, invokeErr := cf.invoke(context.Background(), &http.Client{},
		contentFilterScopeRequest, "my-route", "my-backend", "tools/call", "lookup", hdr, body)
	require.NoError(t, invokeErr)

	require.Equal(t, "my-route", seenEnv.Route)
	require.Equal(t, "my-backend", seenEnv.Backend)
	require.Equal(t, string(contentFilterScopeRequest), seenEnv.Scope)
	require.Equal(t, "tools/call", seenEnv.MCPMethod)
	require.Equal(t, "lookup", seenEnv.Tool)
	decoded, err := base64.StdEncoding.DecodeString(seenEnv.BodyBase64)
	require.NoError(t, err)
	require.Equal(t, body, decoded)
	require.ElementsMatch(t, []string{"abc"}, seenEnv.Headers["X-Request-Id"])
	require.ElementsMatch(t, []string{"u1"}, seenEnv.Headers["X-User-Id"])
	require.NotContains(t, seenEnv.Headers, "Authorization")
}

// --- applyContentFilterOnRequest ------------------------------------------

func TestApplyContentFilterOnRequest_NilFilter(t *testing.T) {
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, nil,
		"r", "b", "lookup", req, nil)
	require.NoError(t, err)
	require.Equal(t, req, got)
}

func TestApplyContentFilterOnRequest_NoRequestScope(t *testing.T) {
	cf := &contentFilter{invokeOnRequest: false, invokeOnResponse: true}
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, nil)
	require.NoError(t, err)
	require.Equal(t, req, got)
}

func TestApplyContentFilterOnRequest_PassReturnsOriginal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionPass})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	req := &jsonrpc.Request{
		ID:     makeID(t, float64(42)),
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup", "arguments": map[string]string{"q": "hello"}}),
	}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got) // bytes equal -> same pointer returned
}

func TestApplyContentFilterOnRequest_RedactReplacesParams(t *testing.T) {
	// Filter returns a completely rewritten request whose params drop secret fields
	replacement := &jsonrpc.Request{
		ID:     makeID(t, "ignored"), // will be overwritten by caller
		Method: "tools/call",
		Params: mustJSON(t, map[string]any{"name": "lookup", "arguments": map[string]string{"q": "REDACTED"}}),
	}
	repBytes, err := jsonrpc.EncodeMessage(replacement)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action:     contentFilterActionRedact,
			BodyBase64: base64.StdEncoding.EncodeToString(repBytes),
			Reason:     "scrubbed",
		})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	originalID := makeID(t, float64(99))
	req := &jsonrpc.Request{ID: originalID, Method: "tools/call", Params: mustJSON(t, map[string]any{"name": "lookup"})}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.NotSame(t, req, got)
	require.Equal(t, originalID, got.ID, "gateway must preserve the original JSON-RPC ID")
	require.Equal(t, "tools/call", got.Method)
	require.Contains(t, string(got.Params), "REDACTED")
}

func TestApplyContentFilterOnRequest_Reject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionReject, Reason: "not allowed"})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.ErrorIs(t, err, errContentFilterRejected)
	require.Contains(t, err.Error(), "not allowed")
}

func TestApplyContentFilterOnRequest_FailOpenOnInvokeError(t *testing.T) {
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:           "http://127.0.0.1:1", // unreachable
		Scopes:        []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		FailurePolicy: filterapi.MCPContentFilterFailurePolicyPassThrough,
	}, "r", "b")
	require.NoError(t, err)
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	got, err := applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{Timeout: 200 * time.Millisecond}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.NoError(t, err)
	require.Same(t, req, got, "fail-open must return original request unchanged")
}

func TestApplyContentFilterOnRequest_FailClosedOnInvokeError(t *testing.T) {
	cf, err := compileContentFilter(&filterapi.MCPContentFilter{
		URL:           "http://127.0.0.1:1", // unreachable
		Scopes:        []filterapi.MCPContentFilterScope{filterapi.MCPContentFilterScopeRequest},
		FailurePolicy: filterapi.MCPContentFilterFailurePolicyFail,
	}, "r", "b")
	require.NoError(t, err)
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err = applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{Timeout: 200 * time.Millisecond}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.ErrorIs(t, err, errContentFilterFailed)
}

func TestApplyContentFilterOnRequest_RejectsInvalidReplacement(t *testing.T) {
	// Replacement body is syntactically JSON-RPC but a *response*, not a *request*.
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	respBytes, err := jsonrpc.EncodeMessage(resp)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action:     contentFilterActionRedact,
			BodyBase64: base64.StdEncoding.EncodeToString(respBytes),
		})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	req := &jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"}
	_, err = applyContentFilterOnRequest(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, http.Header{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "JSON-RPC request")
}

// --- applyContentFilterOnResponse -----------------------------------------

func TestApplyContentFilterOnResponse_NilFilter(t *testing.T) {
	resp := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"ok": true})}
	got, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, nil,
		"r", "b", "lookup", nil, resp, nil)
	require.NoError(t, err)
	require.Equal(t, resp, got)
}

func TestApplyContentFilterOnResponse_RedactReplacesResult(t *testing.T) {
	replacement := &jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{"result": "sanitized"})}
	repBytes, err := jsonrpc.EncodeMessage(replacement)
	require.NoError(t, err)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{
			Action:     contentFilterActionRedact,
			BodyBase64: base64.StdEncoding.EncodeToString(repBytes),
		})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	originalID := makeID(t, float64(100))
	resp := &jsonrpc.Response{ID: originalID, Result: mustJSON(t, map[string]any{"secret": "leaked"})}
	req := &jsonrpc.Request{ID: originalID, Method: "tools/call"}
	got, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup", req, resp, http.Header{})
	require.NoError(t, err)
	require.NotSame(t, resp, got)
	require.Equal(t, originalID, got.ID, "gateway must preserve the original JSON-RPC ID")
	require.Contains(t, string(got.Result), "sanitized")
}

func TestApplyContentFilterOnResponse_Reject(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contentFilterResponse{Action: contentFilterActionReject, Reason: "leaked"})
	}))
	defer srv.Close()
	cf := newTestFilter(t, srv.URL, false)
	_, err := applyContentFilterOnResponse(context.Background(), &mcpLoggerShim{}, &http.Client{}, cf,
		"r", "b", "lookup",
		&jsonrpc.Request{ID: makeID(t, float64(1)), Method: "tools/call"},
		&jsonrpc.Response{ID: makeID(t, float64(1)), Result: mustJSON(t, map[string]any{})},
		http.Header{})
	require.ErrorIs(t, err, errContentFilterRejected)
}

// --- helpers ---------------------------------------------------------------

// mustJSON marshals v and returns the raw bytes. We return []byte (not a
// named RawMessage type) so the result is assignable to both
// encoding/json.RawMessage (used by the MCP SDK's jsonrpc types) and our
// internal json.RawMessage without explicit conversion at each call site.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
