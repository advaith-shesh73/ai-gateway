// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"net"
	"net/http"
	"time"
)

// TunedHTTPTransportConfig captures the knobs that matter for a
// content-filter HTTP client under real load.
//
// The Go stdlib default [http.DefaultTransport] has
// `MaxIdleConnsPerHost = 2`, which is a classic cause of
// connection-pool starvation whenever a single host (typically the PII
// sidecar) receives more than two concurrent requests from one process.
// Under a N-way chunk fan-out (see PIIClient.maxParallelChunks) the
// default pool size produces a TIME_WAIT storm and measurable tail
// latency.
//
// This helper constructs a transport that is tuned for the
// content-filter workload: a small number of hosts (PII, Jira) with a
// bounded fan-out per host.
//
// Field semantics (all fields have sane defaults — see withDefaults):
//
//   - MaxConcurrentPerHost: expected peak in-flight requests to any
//     single downstream host. This is the SINGLE most important knob;
//     the transport sets both [http.Transport.MaxIdleConnsPerHost] and
//     [http.Transport.MaxConnsPerHost] to this value so every chunk in
//     a fan-out gets its own warmed-up conn without a hard ceiling at
//     2. Defaults to 64.
//   - MaxIdleConns: global cap on idle connections across all hosts.
//     Defaults to 256.
//   - IdleConnTimeout: how long an idle connection stays in the pool
//     before being closed. The stdlib default is 90s and we keep that.
//   - DialTimeout: connect deadline; default 5s.
//   - KeepAlive: TCP keepalive interval for dialed connections; default
//     30s. A keepalive on an idle conn prevents the NAT table from
//     silently dropping it.
//   - TLSHandshakeTimeout: default 10s (matches stdlib).
//   - ResponseHeaderTimeout: bounds how long we wait for the response
//     status line after writing the request. Zero disables the timeout
//     (matches stdlib). The PII client applies a per-call context
//     timeout on top, so this is primarily a defence against hung
//     backends during pool warm-up.
//   - ExpectContinueTimeout: default 1s (matches stdlib).
//   - DisableHTTP2: when true, skips HTTP/2 negotiation and forces
//     HTTP/1.1. Defaults to false (HTTP/2 enabled) because the PII
//     sidecar and Jira both support it and HTTP/2 multiplexing
//     eliminates per-host conn-pool pressure entirely. Flip this to
//     true only for backends whose HTTP/2 path is broken.
//   - DisableCompression: passes through to [http.Transport.DisableCompression].
//     Defaults to false.
//
// Zero values in the config are replaced with the defaults above.
// Callers who want an explicit zero (e.g. `ResponseHeaderTimeout: 0`
// to keep the stdlib "no timeout" semantics) should leave the field as
// its zero value; `withDefaults` never overrides an explicit non-zero
// value with a default.
type TunedHTTPTransportConfig struct {
	MaxConcurrentPerHost  int
	MaxIdleConns          int
	IdleConnTimeout       time.Duration
	DialTimeout           time.Duration
	KeepAlive             time.Duration
	TLSHandshakeTimeout   time.Duration
	ResponseHeaderTimeout time.Duration
	ExpectContinueTimeout time.Duration
	DisableHTTP2          bool
	DisableCompression    bool
}

func (c TunedHTTPTransportConfig) withDefaults() TunedHTTPTransportConfig {
	if c.MaxConcurrentPerHost <= 0 {
		c.MaxConcurrentPerHost = 64
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = 256
	}
	if c.IdleConnTimeout <= 0 {
		c.IdleConnTimeout = 90 * time.Second
	}
	if c.DialTimeout <= 0 {
		c.DialTimeout = 5 * time.Second
	}
	if c.KeepAlive <= 0 {
		c.KeepAlive = 30 * time.Second
	}
	if c.TLSHandshakeTimeout <= 0 {
		c.TLSHandshakeTimeout = 10 * time.Second
	}
	if c.ExpectContinueTimeout <= 0 {
		c.ExpectContinueTimeout = 1 * time.Second
	}
	// ResponseHeaderTimeout has "0 = disabled" as a valid stdlib
	// semantic, so do NOT default it here. Callers set it if they
	// want it.
	return c
}

// NewTunedHTTPTransport returns an [http.Transport] tuned for the
// content-filter workload. The returned value is safe for concurrent
// use and may be passed directly as the `Transport` field on an
// [http.Client]. The caller owns lifecycle: call
// [http.Transport.CloseIdleConnections] during process shutdown if
// idle conn reuse across test runs is undesirable.
//
// Example:
//
//	tr := NewTunedHTTPTransport(TunedHTTPTransportConfig{
//	    MaxConcurrentPerHost: 128, // expect up to 128 chunks in flight
//	})
//	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
func NewTunedHTTPTransport(cfg TunedHTTPTransportConfig) *http.Transport {
	c := cfg.withDefaults()
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   c.DialTimeout,
			KeepAlive: c.KeepAlive,
		}).DialContext,
		ForceAttemptHTTP2:     !c.DisableHTTP2,
		MaxIdleConns:          c.MaxIdleConns,
		MaxIdleConnsPerHost:   c.MaxConcurrentPerHost,
		MaxConnsPerHost:       c.MaxConcurrentPerHost,
		IdleConnTimeout:       c.IdleConnTimeout,
		TLSHandshakeTimeout:   c.TLSHandshakeTimeout,
		ResponseHeaderTimeout: c.ResponseHeaderTimeout,
		ExpectContinueTimeout: c.ExpectContinueTimeout,
		DisableCompression:    c.DisableCompression,
	}
}

// NewTunedHTTPClient is a convenience wrapper returning an
// [http.Client] with a tuned transport and an overall per-request
// timeout. The timeout covers the full request lifecycle (connect +
// send + wait for headers + read body); PII/Jira clients additionally
// apply their own per-call context deadline on top, which is the one
// callers should prefer when shedding for back-pressure.
//
// Passing timeout == 0 disables the overall timeout; per-call
// context.WithTimeout should then be used on every call site.
func NewTunedHTTPClient(cfg TunedHTTPTransportConfig, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: NewTunedHTTPTransport(cfg),
		Timeout:   timeout,
	}
}
