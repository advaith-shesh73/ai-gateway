// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestPIIClient_AnonymizeForRoute_IsolatesCacheAcrossRoutes is the
// core L06 guarantee: two different routes sending identical text with
// identical piiContext MUST NOT share a cached redaction, even when
// the cache is warm. This prevents a cross-tenant redaction leak when
// a future PII model update is rolled out to one route before another.
func TestPIIClient_AnonymizeForRoute_IsolatesCacheAcrossRoutes(t *testing.T) {
	// Each call returns a stable response that includes the call
	// sequence number; we can then detect whether two routes really
	// shared a cached value (they'd see the same response number).
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"redacted-v` + strconv.Itoa(int(n)) + `"}`))
	}))
	defer srv.Close()

	cache := NewContentFilterCache(ContentFilterCacheConfig{MaxEntries: 16, TTL: time.Minute})
	c, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          1000,
		MaxParallelChunks: 1,
		Cache:             cache,
		FailClosed:        false,
		Logger:            quietPIILogger(),
	})
	require.NoError(t, err)

	const text = "hello world"
	const piiCtx = "Response|supportgpt|tools/call"

	// First tenant warms the cache.
	out1, err := c.AnonymizeForRoute(context.Background(), text, piiCtx, "route-a", "supportgpt")
	require.NoError(t, err)
	require.Equal(t, "redacted-v1", out1)

	// Different route → must NOT share the cache row; the fake
	// returns a new sequence number, proving a second wire call
	// happened.
	out2, err := c.AnonymizeForRoute(context.Background(), text, piiCtx, "route-b", "supportgpt")
	require.NoError(t, err)
	require.Equal(t, "redacted-v2", out2, "route-b must miss the cache warmed by route-a")

	// Same route → MUST share the cache row, so the fake is not
	// contacted a third time.
	out3, err := c.AnonymizeForRoute(context.Background(), text, piiCtx, "route-a", "supportgpt")
	require.NoError(t, err)
	require.Equal(t, out1, out3, "route-a must hit its own warmed row")
	require.EqualValues(t, 2, calls.Load(), "third call must have been a cache hit, not a wire call")
}

// TestPIIClient_AnonymizeForRoute_IsolatesCacheAcrossBackends proves
// the same invariant for backend separation: even within one route,
// two different backends with identical piiContext must have
// independent cache rows.
func TestPIIClient_AnonymizeForRoute_IsolatesCacheAcrossBackends(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"redacted-v` + strconv.Itoa(int(n)) + `"}`))
	}))
	defer srv.Close()

	cache := NewContentFilterCache(ContentFilterCacheConfig{MaxEntries: 16, TTL: time.Minute})
	c, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          1000,
		MaxParallelChunks: 1,
		Cache:             cache,
		FailClosed:        false,
		Logger:            quietPIILogger(),
	})
	require.NoError(t, err)

	out1, err := c.AnonymizeForRoute(context.Background(), "text", "ctx", "route", "backend-a")
	require.NoError(t, err)
	out2, err := c.AnonymizeForRoute(context.Background(), "text", "ctx", "route", "backend-b")
	require.NoError(t, err)
	require.NotEqual(t, out1, out2, "backends must not share cache rows")
	require.EqualValues(t, 2, calls.Load())
}

// TestPIIClient_Anonymize_BackwardsCompatible verifies the original
// [PIIClient.Anonymize] entry point (no route/backend) still works and
// still shares cache rows for callers who haven't migrated. This is
// what keeps the parity-focused unit-test suite passing.
func TestPIIClient_Anonymize_BackwardsCompatible(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"redacted"}`))
	}))
	defer srv.Close()

	cache := NewContentFilterCache(ContentFilterCacheConfig{MaxEntries: 16, TTL: time.Minute})
	c, err := NewPIIClient(&PIIClientConfig{
		HTTPClient:        &http.Client{Timeout: 2 * time.Second},
		URL:               srv.URL,
		Timeout:           2 * time.Second,
		MaxChars:          1000,
		MaxParallelChunks: 1,
		Cache:             cache,
		FailClosed:        false,
		Logger:            quietPIILogger(),
	})
	require.NoError(t, err)

	_, err = c.Anonymize(context.Background(), "hello", "ctx")
	require.NoError(t, err)
	_, err = c.Anonymize(context.Background(), "hello", "ctx")
	require.NoError(t, err)
	require.EqualValues(t, 1, calls.Load(), "second call must be a cache hit")
}
