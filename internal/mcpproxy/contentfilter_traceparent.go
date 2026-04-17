// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// TraceHeaderTraceparent is the canonical W3C Trace Context header name.
// Capitalized exactly as specified by the W3C recommendation so the
// HTTP MIME-normalizer in [http.Header.Set] preserves it across
// round-trips.
const TraceHeaderTraceparent = "Traceparent"

// TraceHeaderTracestate is the companion header carrying vendor-
// specific trace state. Not every backend consumes it but emitting
// both is cheap and the standard.
const TraceHeaderTracestate = "Tracestate"

// headerCarrier adapts [http.Header] to the OpenTelemetry propagation
// carrier interface without reaching for net/http/textproto. Callers
// don't construct this directly — it exists only so
// [TraceparentOutboundHeaders] can invoke the global propagator on a
// header we own.
type headerCarrier http.Header

func (c headerCarrier) Get(key string) string        { return http.Header(c).Get(key) }
func (c headerCarrier) Set(key string, value string) { http.Header(c).Set(key, value) }
func (c headerCarrier) Keys() []string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	return keys
}

// TraceparentOutboundHeaders returns an OutboundHeaders callback
// suitable for [PIIClientConfig.OutboundHeaders] or
// [JiraClientConfig.OutboundHeaders]. Each invocation asks the global
// OpenTelemetry propagator to inject the current span context into a
// fresh [http.Header] and returns it.
//
// Why a propagator and not a hand-coded traceparent parse?
//   - The propagator handles W3C Trace Context + Baggage + any other
//     carrier registered at bootstrap (OTel SDK usually registers
//     `tracecontext` + `baggage` by default). Hand-coding would skip
//     baggage and drop tracestate.
//   - Bootstrap code can install a custom propagator (e.g. for
//     zipkin B3 compatibility) without any change in this file.
//
// Zero span context in the ctx produces an empty header map: the
// downstream receives no Traceparent, which is the correct signal
// that the caller has no active span to propagate. Callers that want
// to force a new root span must wrap their context in
// `otel.Tracer(...).Start(...)` before invoking this hook.
//
// Safe to call from many goroutines. Returns a new header map on
// every invocation so callers can freely mutate / augment it.
func TraceparentOutboundHeaders() func(context.Context) http.Header {
	return func(ctx context.Context) http.Header {
		h := http.Header{}
		otel.GetTextMapPropagator().Inject(ctx, headerCarrier(h))
		return h
	}
}

// CombineOutboundHeaders composes multiple OutboundHeaders callbacks
// into a single one. Headers from later callbacks overwrite earlier
// ones key-by-key; multi-valued headers from later callbacks REPLACE
// (not append to) earlier values. Use when a caller wants the
// traceparent hook AND some static headers without writing a custom
// closure.
//
// A nil element in hooks is skipped. The returned callback is itself
// nil-safe: calling it with a nil context returns an empty header
// map because the individual hooks handle the nil-ctx case.
func CombineOutboundHeaders(hooks ...func(context.Context) http.Header) func(context.Context) http.Header {
	// Defensive copy so later mutations of the hooks slice by the
	// caller cannot change our behaviour.
	cp := make([]func(context.Context) http.Header, 0, len(hooks))
	for _, h := range hooks {
		if h != nil {
			cp = append(cp, h)
		}
	}
	if len(cp) == 0 {
		return nil
	}
	return func(ctx context.Context) http.Header {
		out := http.Header{}
		for _, h := range cp {
			for k, vs := range h(ctx) {
				// Replace any prior value with the later hook's value.
				out[k] = append([]string(nil), vs...)
			}
		}
		return out
	}
}

// StaticOutboundHeaders returns a hook that always yields the same
// headers. Intended for cases like a static `X-Source: mcp-gateway`
// tag that every outbound request needs. The returned map is cloned
// per call so callers can mutate it freely.
func StaticOutboundHeaders(h http.Header) func(context.Context) http.Header {
	// Defensive clone at construction time so later mutations of the
	// caller's header map do not leak into future calls.
	clone := make(http.Header, len(h))
	for k, vs := range h {
		clone[k] = append([]string(nil), vs...)
	}
	return func(context.Context) http.Header {
		out := make(http.Header, len(clone))
		for k, vs := range clone {
			out[k] = append([]string(nil), vs...)
		}
		return out
	}
}

var _ propagation.TextMapCarrier = headerCarrier{}
