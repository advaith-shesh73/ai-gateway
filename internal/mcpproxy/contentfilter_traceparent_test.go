// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package mcpproxy

import (
	"context"
	"net/http"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// tracecontextPattern matches the W3C traceparent format:
// version "-" trace-id "-" parent-id "-" trace-flags.
var tracecontextPattern = regexp.MustCompile(`^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

// installTracecontextPropagator sets the global propagator for the
// duration of a test and restores the previous one on cleanup.
func installTracecontextPropagator(t *testing.T) {
	t.Helper()
	prev := otel.GetTextMapPropagator()
	otel.SetTextMapPropagator(propagation.TraceContext{})
	t.Cleanup(func() { otel.SetTextMapPropagator(prev) })
}

func TestTraceparentOutboundHeaders_NoSpanReturnsEmpty(t *testing.T) {
	installTracecontextPropagator(t)
	hook := TraceparentOutboundHeaders()
	h := hook(context.Background())
	require.Empty(t, h.Get(TraceHeaderTraceparent))
}

func TestTraceparentOutboundHeaders_InjectsFromActiveSpan(t *testing.T) {
	installTracecontextPropagator(t)

	tp := sdktrace.NewTracerProvider()
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	ctx, span := tp.Tracer("test").Start(context.Background(), "outer")
	defer span.End()

	hook := TraceparentOutboundHeaders()
	h := hook(ctx)
	tp2 := h.Get(TraceHeaderTraceparent)
	require.NotEmpty(t, tp2, "expected traceparent header to be injected")
	require.True(t, tracecontextPattern.MatchString(tp2),
		"traceparent header %q does not match W3C format", tp2)
}

func TestStaticOutboundHeaders_ClonesPerCall(t *testing.T) {
	src := http.Header{"X-Source": []string{"mcp-gateway"}}
	hook := StaticOutboundHeaders(src)
	// Mutate the original to confirm the hook kept its own copy.
	src.Set("X-Source", "mutated")

	h1 := hook(context.Background())
	require.Equal(t, "mcp-gateway", h1.Get("X-Source"))
	// Mutate h1; the next call must still yield the pristine value.
	h1.Set("X-Source", "mutated-by-caller")
	h2 := hook(context.Background())
	require.Equal(t, "mcp-gateway", h2.Get("X-Source"))
}

func TestCombineOutboundHeaders_LaterOverridesEarlier(t *testing.T) {
	a := StaticOutboundHeaders(http.Header{"X-Source": []string{"a"}})
	b := StaticOutboundHeaders(http.Header{"X-Source": []string{"b"}, "X-Extra": []string{"yes"}})
	hook := CombineOutboundHeaders(a, b)
	require.NotNil(t, hook)
	h := hook(context.Background())
	require.Equal(t, "b", h.Get("X-Source"))
	require.Equal(t, "yes", h.Get("X-Extra"))
}

func TestCombineOutboundHeaders_NilInputsFiltered(t *testing.T) {
	require.Nil(t, CombineOutboundHeaders())
	require.Nil(t, CombineOutboundHeaders(nil, nil))

	a := StaticOutboundHeaders(http.Header{"X-A": []string{"1"}})
	hook := CombineOutboundHeaders(nil, a, nil)
	require.NotNil(t, hook)
	require.Equal(t, "1", hook(context.Background()).Get("X-A"))
}
