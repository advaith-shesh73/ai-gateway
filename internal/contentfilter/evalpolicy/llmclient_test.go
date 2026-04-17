// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package evalpolicy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/envoyproxy/ai-gateway/internal/json"
)

// makeHTTPClient is a small wrapper that builds an httpLLMClient
// against the given test server. Centralising it keeps the
// individual tests focused on behaviour. The reqHook parameter is a
// reserved extension point so future tests can inspect outbound
// requests without duplicating this helper; renaming it to `_` would
// break that intent.
func makeHTTPClient(t *testing.T, serverURL string, _ func(r *http.Request, body []byte)) *httpLLMClient {
	t.Helper()
	t.Setenv("CF_TEST_KEY", "secret-token")
	c := Config{
		Endpoint:              serverURL,
		Model:                 "test-model",
		APIKeyEnv:             "CF_TEST_KEY",
		TimeoutSeconds:        5,
		Temperature:           0.0,
		InsecureSkipTLSVerify: false,
	}
	llm := newHTTPLLMClient(&c)
	return llm
}

func TestHTTPLLMClient_SuccessRoundtrip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "Bearer secret-token", r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var decoded struct {
			Model       string `json:"model"`
			Stream      bool   `json:"stream"`
			Temperature any    `json:"temperature"`
			Messages    []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		require.NoError(t, json.Unmarshal(body, &decoded))
		require.Equal(t, "test-model", decoded.Model)
		require.False(t, decoded.Stream)
		require.Len(t, decoded.Messages, 2)
		require.Equal(t, "system", decoded.Messages[0].Role)
		require.Equal(t, "user", decoded.Messages[1].Role)

		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"filtered body"}}]}`))
	}))
	defer srv.Close()

	c := makeHTTPClient(t, srv.URL, nil)
	out, err := c.Complete(context.Background(), "sys", "usr")
	require.NoError(t, err)
	require.Equal(t, "filtered body", out)
}

func TestHTTPLLMClient_ReasoningContentFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"","reasoning_content":"from reasoning"}}]}`))
	}))
	defer srv.Close()

	c := makeHTTPClient(t, srv.URL, nil)
	out, err := c.Complete(context.Background(), "sys", "usr")
	require.NoError(t, err)
	require.Equal(t, "from reasoning", out,
		"must fall back to reasoning_content when content is empty")
}

func TestHTTPLLMClient_EmptyMessageReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":""}}]}`))
	}))
	defer srv.Close()

	c := makeHTTPClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", "usr")
	require.ErrorContains(t, err, "empty content")
}

func TestHTTPLLMClient_NoChoicesReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[]}`))
	}))
	defer srv.Close()

	c := makeHTTPClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", "usr")
	require.ErrorContains(t, err, "no choices")
}

func TestHTTPLLMClient_Non2xxSurfacesStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`upstream tripped`))
	}))
	defer srv.Close()

	c := makeHTTPClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", "usr")
	require.ErrorContains(t, err, "HTTP 503")
	require.ErrorContains(t, err, "upstream tripped")
}

func TestHTTPLLMClient_MissingAPIKeyErrorsEarly(t *testing.T) {
	c := Config{
		Endpoint:       "http://ignored",
		Model:          "test-model",
		APIKeyEnv:      "CF_DEFINITELY_UNSET_KEY_NAME",
		TimeoutSeconds: 1,
	}
	client := newHTTPLLMClient(&c)
	_, err := client.Complete(context.Background(), "sys", "usr")
	require.ErrorContains(t, err, "API key not found")
}

func TestHTTPLLMClient_RespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Hang until client disconnects.
		select {
		case <-r.Context().Done():
			return
		case <-time.After(5 * time.Second):
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer srv.Close()

	c := makeHTTPClient(t, srv.URL, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling

	_, err := c.Complete(ctx, "sys", "usr")
	require.Error(t, err)
	require.True(t,
		strings.Contains(err.Error(), "context canceled") ||
			strings.Contains(err.Error(), "canceled"),
		"expected context cancellation to surface, got %v", err)
}
