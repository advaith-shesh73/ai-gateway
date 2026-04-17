// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestTunedHTTPTransport_AppliesDefaults(t *testing.T) {
	tr := NewTunedHTTPTransport(TunedHTTPTransportConfig{})
	require.Equal(t, 64, tr.MaxIdleConnsPerHost)
	require.Equal(t, 64, tr.MaxConnsPerHost)
	require.Equal(t, 256, tr.MaxIdleConns)
	require.Equal(t, 90*time.Second, tr.IdleConnTimeout)
	require.Equal(t, 10*time.Second, tr.TLSHandshakeTimeout)
	require.Equal(t, 1*time.Second, tr.ExpectContinueTimeout)
	require.True(t, tr.ForceAttemptHTTP2)
}

func TestTunedHTTPTransport_RespectsOverrides(t *testing.T) {
	tr := NewTunedHTTPTransport(TunedHTTPTransportConfig{
		MaxConcurrentPerHost: 8,
		MaxIdleConns:         16,
		IdleConnTimeout:      2 * time.Second,
		DisableCompression:   true,
	})
	require.Equal(t, 8, tr.MaxIdleConnsPerHost)
	require.Equal(t, 8, tr.MaxConnsPerHost)
	require.Equal(t, 16, tr.MaxIdleConns)
	require.Equal(t, 2*time.Second, tr.IdleConnTimeout)
	require.True(t, tr.DisableCompression)
}

func TestTunedHTTPTransport_ResponseHeaderTimeoutNotDefaulted(t *testing.T) {
	// Zero is a valid stdlib sentinel meaning "no timeout".
	// withDefaults must NOT silently override it.
	tr := NewTunedHTTPTransport(TunedHTTPTransportConfig{})
	require.Equal(t, time.Duration(0), tr.ResponseHeaderTimeout)
}

func TestTunedHTTPClient_UsesConfiguredTimeout(t *testing.T) {
	c := NewTunedHTTPClient(TunedHTTPTransportConfig{}, 7*time.Second)
	require.Equal(t, 7*time.Second, c.Timeout)
	// Underlying transport is a *http.Transport.
	_, ok := c.Transport.(*http.Transport)
	require.True(t, ok, "expected *http.Transport as underlying transport")
}

// TestTunedHTTPTransport_ServesConcurrentRequests is a smoke test: a
// modestly configured tuned transport must NOT deadlock or error
// under a simple 2x N-way concurrent load against an httptest server.
// The value of this test is that it exercises the production code
// path end-to-end (dial + send + read + close) with the real pool
// sizing, so a mis-tuned default would surface via a 5xx or timeout.
func TestTunedHTTPTransport_ServesConcurrentRequests(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)

	client := NewTunedHTTPClient(TunedHTTPTransportConfig{
		MaxConcurrentPerHost: 16,
	}, 5*time.Second)

	const N = 32
	var wg sync.WaitGroup
	errs := make(chan error, N)
	for range N {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(srv.URL)
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("unexpected error: %v", err)
	}
}
