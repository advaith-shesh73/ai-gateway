// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package contentfilter

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/contentfilter/wire"
	"github.com/envoyproxy/ai-gateway/internal/json"
)

// canned policy behaviours used by the server tests below. Each is
// intentionally trivial so we can assert on the Server's handling of
// its verdict rather than any internal logic.

// passingPolicy always returns ActionPass.
type passingPolicy struct{}

func (passingPolicy) Name() string { return "passing-stub" }
func (passingPolicy) Filter(_ context.Context, _ *wire.FilterRequest) (*wire.FilterResponse, error) {
	return &wire.FilterResponse{Action: string(wire.ActionPass)}, nil
}

// redactPolicy always returns ActionRedact with a fixed body.
type redactPolicy struct{ body []byte }

func (redactPolicy) Name() string { return "redact-stub" }
func (r redactPolicy) Filter(_ context.Context, _ *wire.FilterRequest) (*wire.FilterResponse, error) {
	return &wire.FilterResponse{
		Action:     string(wire.ActionRedact),
		BodyBase64: base64.StdEncoding.EncodeToString(r.body),
		Reason:     "test-redact",
	}, nil
}

// erroringPolicy always returns an error. Used to verify that the
// server surfaces policy errors as 500s (gateway applies its own
// FailurePolicy) rather than folding them into ActionReject.
type erroringPolicy struct{}

func (erroringPolicy) Name() string { return "erroring-stub" }
func (erroringPolicy) Filter(_ context.Context, _ *wire.FilterRequest) (*wire.FilterResponse, error) {
	return nil, errors.New("policy boom")
}

// unknownActionPolicy returns a verdict with a made-up action
// string. The server MUST reject this — policy typos should be
// visible to operators immediately, not leaked to the gateway.
type unknownActionPolicy struct{}

func (unknownActionPolicy) Name() string { return "unknown-stub" }
func (unknownActionPolicy) Filter(_ context.Context, _ *wire.FilterRequest) (*wire.FilterResponse, error) {
	return &wire.FilterResponse{Action: "shrug"}, nil
}

// newTestServer builds a Server, mounts it on an httptest.Server,
// and returns both. The caller must defer srv.Close().
func newTestServer(t *testing.T, p Policy) *httptest.Server {
	t.Helper()
	s, err := NewServer(p, 2*time.Second, nil)
	require.NoError(t, err)
	return httptest.NewServer(s.Handler())
}

// postFilter issues a POST /filter with the given body and returns
// (status, decoded response, raw body).
func postFilter(t *testing.T, srv *httptest.Server, req any) (int, wire.FilterResponse, []byte) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)

	resp, err := http.Post(srv.URL+"/filter", "application/json", bytes.NewReader(body))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var decoded wire.FilterResponse
	if resp.StatusCode/100 == 2 {
		require.NoError(t, json.Unmarshal(raw, &decoded))
	}
	return resp.StatusCode, decoded, raw
}

func TestServer_PassVerdictIsReturnedVerbatim(t *testing.T) {
	srv := newTestServer(t, passingPolicy{})
	defer srv.Close()

	req := wire.FilterRequest{
		Scope:      string(wire.ScopeResponse),
		Tool:       "x",
		BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Headers:    map[string][]string{},
	}
	status, body, _ := postFilter(t, srv, req)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, string(wire.ActionPass), body.Action)
}

func TestServer_RedactVerdictIsReturnedVerbatim(t *testing.T) {
	want := []byte(`{"jsonrpc":"2.0","result":{}}`)
	srv := newTestServer(t, redactPolicy{body: want})
	defer srv.Close()

	req := wire.FilterRequest{
		Scope:      string(wire.ScopeResponse),
		Tool:       "x",
		BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Headers:    map[string][]string{},
	}
	status, body, _ := postFilter(t, srv, req)
	require.Equal(t, http.StatusOK, status)
	require.Equal(t, string(wire.ActionRedact), body.Action)
	got, err := base64.StdEncoding.DecodeString(body.BodyBase64)
	require.NoError(t, err)
	require.Equal(t, want, got)
	require.Equal(t, "test-redact", body.Reason)
}

func TestServer_PolicyErrorReturns500(t *testing.T) {
	srv := newTestServer(t, erroringPolicy{})
	defer srv.Close()

	req := wire.FilterRequest{
		Scope:      string(wire.ScopeResponse),
		Tool:       "x",
		BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Headers:    map[string][]string{},
	}
	status, _, raw := postFilter(t, srv, req)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, string(raw), "policy error")
}

func TestServer_UnknownActionReturns500(t *testing.T) {
	srv := newTestServer(t, unknownActionPolicy{})
	defer srv.Close()

	req := wire.FilterRequest{
		Scope:      string(wire.ScopeResponse),
		Tool:       "x",
		BodyBase64: base64.StdEncoding.EncodeToString([]byte(`{}`)),
		Headers:    map[string][]string{},
	}
	status, _, raw := postFilter(t, srv, req)
	require.Equal(t, http.StatusInternalServerError, status)
	require.Contains(t, string(raw), "unknown action")
}

func TestServer_BadJSONReturns400(t *testing.T) {
	srv := newTestServer(t, passingPolicy{})
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/filter", "application/json",
		bytes.NewReader([]byte("not json at all")))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestServer_HealthzReturns200(t *testing.T) {
	srv := newTestServer(t, passingPolicy{})
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestServer_OversizedBodyReturns413(t *testing.T) {
	srv := newTestServer(t, passingPolicy{})
	defer srv.Close()

	// Craft a body just larger than the cap.
	huge := strings.Repeat("x", maxFilterRequestBytes+16)
	resp, err := http.Post(srv.URL+"/filter", "application/json",
		bytes.NewReader([]byte(huge)))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

func TestServer_NilPolicyRejectedAtConstruction(t *testing.T) {
	_, err := NewServer(nil, time.Second, nil)
	require.ErrorContains(t, err, "requires a policy")
}
