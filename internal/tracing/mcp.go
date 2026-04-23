// Copyright Envoy AI Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package tracing

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"

	"github.com/envoyproxy/ai-gateway/internal/lang"
	"github.com/envoyproxy/ai-gateway/internal/tracing/tracingapi"
)

// defaultBaggageSpanAttributes maps well-known W3C baggage keys (set by
// clients on inbound HTTP requests per the client contract) to OTel span
// attribute keys. Keeping this as a static default map keeps the PII
// surface small: only these three correlation identifiers are copied onto
// spans by default. Any other baggage keys the client sets still propagate
// to downstream services via the baggage header but are not promoted to
// span attributes unless the operator opts in via [mcpTraceBaggageAttrsEnv].
var defaultBaggageSpanAttributes = map[string]string{
	"ticket": "mcp.client.ticket",
	"user":   "mcp.client.user",
	"role":   "mcp.client.role",
}

// mcpTraceBaggageAttrsEnv is an optional env var the operator can set to
// override the promoted baggage key set. Value is a comma-separated list
// of baggage keys, e.g. `MCP_TRACE_BAGGAGE_ATTRS=ticket,user,role`. When
// unset, [defaultBaggageSpanAttributes] is used. When set to an empty
// string, NO baggage keys are promoted to span attributes (baggage still
// propagates on the wire for downstream services).
const mcpTraceBaggageAttrsEnv = "MCP_TRACE_BAGGAGE_ATTRS"

// maxBaggageAttrValueBytes caps how many bytes of a baggage value we copy
// onto a span attribute. Baggage is free-form client-supplied data: even
// though the client contract only promises opaque short identifiers, a
// misbehaving or malicious client could stuff an arbitrarily large value
// into a known key. Truncating here bounds the per-span attribute size so
// a bad client cannot inflate OTLP export payloads or trip
// backend-specific attribute-length limits. The value is in bytes, not
// runes, to keep the bound independent of UTF-8 width.
const maxBaggageAttrValueBytes = 128

// baggageAttrsFromEnv returns the effective baggage-to-attribute map for
// the process. Precedence: [mcpTraceBaggageAttrsEnv] override, then the
// static [defaultBaggageSpanAttributes] default. Unknown or empty keys in
// the env var are skipped; duplicate keys are deduplicated. The returned
// map is fresh on every call so callers can safely mutate it.
func baggageAttrsFromEnv() map[string]string {
	raw, ok := os.LookupEnv(mcpTraceBaggageAttrsEnv)
	if !ok {
		out := make(map[string]string, len(defaultBaggageSpanAttributes))
		for k, v := range defaultBaggageSpanAttributes {
			out[k] = v
		}
		return out
	}
	// Empty-string override means "promote nothing"; returning an empty
	// map is intentional and distinct from the unset case above.
	out := map[string]string{}
	for _, key := range strings.Split(raw, ",") {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		out[key] = "mcp.client." + key
	}
	return out
}

// truncateBaggageAttrValue enforces the [maxBaggageAttrValueBytes] cap.
// Values at or below the cap are returned unchanged. Values above the cap
// are truncated to the cap and an ellipsis marker is appended so the
// downstream consumer can see the value was clipped. Truncation is
// byte-based; if the cap falls inside a multi-byte rune we back up to the
// previous rune boundary so the result stays valid UTF-8.
func truncateBaggageAttrValue(v string) string {
	if len(v) <= maxBaggageAttrValueBytes {
		return v
	}
	cut := maxBaggageAttrValueBytes
	for cut > 0 && v[cut]&0xC0 == 0x80 {
		cut--
	}
	return v[:cut] + "..."
}

// Ensure mcpSpan implements [tracingapi.MCPSpan].
var _ tracingapi.MCPSpan = (*mcpSpan)(nil)

// Ensure mcpTracer implements [tracingapi.MCPTracer].
var _ tracingapi.MCPTracer = (*mcpTracer)(nil)

// mcpSpan is an implementation of [tracingapi.MCPSpan].
type mcpSpan struct {
	span trace.Span
}

// RecordRouteToBackend implements [tracingapi.MCPSpan.RecordRouteToBackend].
func (s mcpSpan) RecordRouteToBackend(backend string, sessionID string, isNew bool) {
	s.span.AddEvent("route to backend", trace.WithAttributes(
		attribute.String("mcp.backend.name", backend),
		attribute.String("mcp.session.id", sessionID),
		attribute.Bool("mcp.session.new", isNew),
	))
}

// EndSpanOnError implements [tracingapi.MCPSpan.EndSpanOnError].
func (s mcpSpan) EndSpanOnError(errType string, err error) {
	s.span.AddEvent("exception", trace.WithAttributes(
		attribute.String("exception.type", errType),
		attribute.String("exception.message", err.Error()),
	))
	s.span.SetStatus(codes.Error, err.Error())
	s.span.End()
}

// EndSpan implements [tracingapi.MCPSpan.EndSpan].
func (s mcpSpan) EndSpan() {
	s.span.SetStatus(codes.Ok, "")
	s.span.End()
}

// mcpTracer is an implementation of [tracingapi.MCPTracer].
type mcpTracer struct {
	tracer            trace.Tracer
	propagator        propagation.TextMapPropagator
	attributeMappings map[string]string
	// baggageAttrs is the effective baggage-key -> span-attribute map for
	// this tracer. Resolved once at construction from
	// [mcpTraceBaggageAttrsEnv] so per-request work stays cheap and so
	// env changes take effect at process restart (same lifecycle as the
	// rest of the OTel config that [NewTracingFromEnv] reads).
	baggageAttrs map[string]string
}

func newMCPTracer(tracer trace.Tracer, propagator propagation.TextMapPropagator, attributeMappings map[string]string) tracingapi.MCPTracer {
	return mcpTracer{
		tracer:            tracer,
		propagator:        propagator,
		attributeMappings: attributeMappings,
		baggageAttrs:      baggageAttrsFromEnv(),
	}
}

// StartSpanAndInjectMeta starts a new MCP span for req and injects the
// resulting trace context back into both the MCP `_meta` map on param and
// the passed-in HTTP `headers`.
//
// Side effects (MUTATION):
//   - `param` is mutated: the MCP `_meta` map is created if nil and is
//     updated to carry the new span's trace context for downstream MCP
//     hops.
//   - `headers` is mutated: the OTel propagator writes `traceparent` /
//     `tracestate` / `baggage` so any upstream HTTP hop driven off the
//     same header set sees the gateway-created span as its parent. This
//     overwrites any existing values for those keys. Callers that need
//     the unmodified inbound headers must clone them first.
//
// PII contract: well-known baggage keys (see [defaultBaggageSpanAttributes]
// or [mcpTraceBaggageAttrsEnv]) are promoted onto the span under
// `mcp.client.*` attributes. Operators opt in which keys get promoted;
// values are capped at [maxBaggageAttrValueBytes] to bound attribute
// size against misbehaving clients. The full baggage header still
// propagates to downstream services unchanged so opaque keys reach
// pii-service + evalpolicy for correlation without being exposed on
// spans. Callers must not put secrets or request bodies into baggage --
// the W3C contract treats baggage as user-visible metadata.
func (m mcpTracer) StartSpanAndInjectMeta(ctx context.Context, req *jsonrpc.Request, param mcp.Params, headers http.Header) tracingapi.MCPSpan {
	attrs := []attribute.KeyValue{
		attribute.String("mcp.protocol.version", "2025-06-18"),
		attribute.String("mcp.transport", "http"),
		attribute.String("mcp.request.id", fmt.Sprintf("%v", req.ID)),
		attribute.String("mcp.method.name", req.Method),
	}
	attrs = append(attrs, getMCPParamsAsAttributes(param)...)

	for srcName, targetName := range m.attributeMappings {
		// Check if the attribute is present in the metadata first, as this is the common place to add custom attributes
		// in MCP requests. Fall back to headers if not found in metadata.
		// If the attribute is not found there, check if there is any custom header to map.
		if metaValue := lang.CaseInsensitiveValue(param.GetMeta(), srcName); metaValue != "" {
			attrs = append(attrs, attribute.String(targetName, metaValue))
		} else if headerValue := headers.Get(srcName); headerValue != "" { // this is case-insensitive
			attrs = append(attrs, attribute.String(targetName, headerValue))
		}
	}

	// Extract trace context and baggage. HTTP headers are the primary
	// source because the client contract (W3C Trace Context + baggage) is
	// carried over HTTP. MCP `_meta` is a secondary source for
	// protocol-level propagation (e.g. nested MCP calls) and is applied
	// after headers so that meta-carried trace context can override when
	// present -- this preserves the pre-existing behavior for callers that
	// only set trace context via `_meta`.
	parentCtx := ctx
	if headers != nil {
		parentCtx = m.propagator.Extract(parentCtx, propagation.HeaderCarrier(headers))
	}
	mutableMeta := param.GetMeta()
	if mutableMeta == nil {
		mutableMeta = make(map[string]any)
	}
	mc := metaMapCarrier{
		m: mutableMeta,
	}
	if hasTraceKey(mutableMeta) {
		parentCtx = m.propagator.Extract(parentCtx, mc)
	}

	// Copy well-known baggage keys onto span attributes. The baggage
	// itself still propagates via [propagator.Inject] below -- this just
	// surfaces correlation identifiers (ticket/user/role by default, or
	// whatever keys the operator opted into via [mcpTraceBaggageAttrsEnv])
	// on the span so operators can find all traces for a ticket or user
	// without joining against the baggage header.
	//
	// Empty values are skipped so a client that sets `ticket=` (no value)
	// does not create a span attribute that is impossible to query on.
	// Oversized values are truncated to [maxBaggageAttrValueBytes] so a
	// misbehaving client cannot inflate span export payloads.
	if bag := baggage.FromContext(parentCtx); bag.Len() > 0 {
		for key, attrKey := range m.baggageAttrs {
			member := bag.Member(key)
			if member.Key() == "" {
				continue
			}
			value := member.Value()
			if value == "" {
				continue
			}
			attrs = append(attrs, attribute.String(attrKey, truncateBaggageAttrValue(value)))
		}
	}

	// Start the span with options appropriate for the semantic convention.
	// Convert method name to span name following mcp-go SDK patterns
	spanName := getSpanName(req.Method)
	newCtx, span := m.tracer.Start(parentCtx, spanName, trace.WithSpanKind(trace.SpanKindClient))

	// Always inject trace context into the MCP `_meta` mutation so the
	// MCP-protocol carrier is populated. This ensures trace propagation
	// works for downstream MCP hops and even for unsampled spans.
	m.propagator.Inject(newCtx, mc)
	param.SetMeta(mc.m)
	// Also inject into the inbound HTTP headers so any downstream HTTP
	// hop driven off `headers` (e.g. the upstream MCP request built from
	// the same header set) sees the updated trace context and baggage.
	if headers != nil {
		m.propagator.Inject(newCtx, propagation.HeaderCarrier(headers))
	}

	// Only record request attributes if span is recording (sampled).
	if span.IsRecording() {
		span.SetAttributes(attrs...)
		return &mcpSpan{span: span}
	}

	return nil
}

// hasTraceKey reports whether the MCP `_meta` map contains a W3C Trace
// Context key, so we only apply meta-based extraction when meta actually
// carries a trace context. Extracting from an empty carrier is harmless
// but extracting from a carrier that only contains unrelated keys can
// overwrite a valid span context populated from HTTP headers.
func hasTraceKey(meta map[string]any) bool {
	if len(meta) == 0 {
		return false
	}
	for _, k := range []string{"traceparent", "tracestate", "baggage"} {
		if _, ok := meta[k]; ok {
			return true
		}
	}
	return false
}

func getMCPParamsAsAttributes(p mcp.Params) []attribute.KeyValue {
	var attrs []attribute.KeyValue
	switch params := p.(type) {
	case *mcp.InitializeParams:
		if params.ClientInfo != nil {
			attrs = append(attrs,
				attribute.String("mcp.client.name", params.ClientInfo.Name),
				attribute.String("mcp.client.title", params.ClientInfo.Title),
				attribute.String("mcp.client.version", params.ClientInfo.Version),
			)
		}
	case *mcp.CallToolParams:
		attrs = append(attrs, attribute.String("mcp.tool.name", params.Name))
	case *mcp.GetPromptParams:
		attrs = append(attrs, attribute.String("mcp.prompt.name", params.Name))
	case *mcp.SetLoggingLevelParams:
		attrs = append(attrs, attribute.String("mcp.logging.level", string(params.Level)))
	case *mcp.ListResourcesParams:
	case *mcp.ReadResourceParams:
		attrs = append(attrs, attribute.String("mcp.resource.uri", params.URI))
	case *mcp.SubscribeParams:
		attrs = append(attrs, attribute.String("mcp.resource.uri", params.URI))
	case *mcp.UnsubscribeParams:
		attrs = append(attrs, attribute.String("mcp.resource.uri", params.URI))
	case *mcp.ProgressNotificationParams:
		if params.Progress != 0 {
			attrs = append(attrs, attribute.Float64("mcp.notifications.progress", params.Progress))
		}
		if params.ProgressToken != nil {
			attrs = append(attrs, attribute.String("mcp.notifications.progress.token", fmt.Sprintf("%v", params.ProgressToken)))
		}
		if len(params.Message) > 0 {
			attrs = append(attrs, attribute.String("mcp.notifications.progress.message", params.Message))
		}
	case *mcp.CompleteParams:
		if len(params.Argument.Name) > 0 {
			attrs = append(attrs, attribute.String("mcp.complete.argument.name", params.Argument.Name))
		}
		if len(params.Argument.Value) > 0 {
			attrs = append(attrs, attribute.String("mcp.complete.argument.value", params.Argument.Value))
		}

	}

	return attrs
}

// Ensure metaMapCarrier implements the [propagation.TextMapCarrier] interface.
var _ propagation.TextMapCarrier = metaMapCarrier{}

// metaMapCarrier adapts a map[string]any to implement the TextMapCarrier interface.
type metaMapCarrier struct {
	m map[string]any
}

// Get implements [propagation.TextMapCarrier.Get].
func (c metaMapCarrier) Get(key string) string {
	return fmt.Sprintf("%v", c.m[key])
}

// Set implements [propagation.TextMapCarrier.Set].
func (c metaMapCarrier) Set(key string, value string) {
	c.m[key] = value
}

// Keys implements [propagation.TextMapCarrier.Keys].
func (c metaMapCarrier) Keys() []string {
	keys := make([]string, 0, len(c.m))
	for k := range c.m {
		keys = append(keys, k)
	}

	return keys
}

// getSpanName converts MCP method names to span names following mcp-go SDK patterns.
func getSpanName(method string) string {
	switch method {
	case "initialize":
		return "Initialize"
	case "tools/list":
		return "ListTools"
	case "tools/call":
		return "CallTool"
	case "prompts/list":
		return "ListPrompts"
	case "prompts/get":
		return "GetPrompt"
	case "resources/list":
		return "ListResources"
	case "resources/read":
		return "ReadResource"
	case "resources/subscribe":
		return "Subscribe"
	case "resources/unsubscribe":
		return "Unsubscribe"
	case "resources/templates/list":
		return "ListResourceTemplates"
	case "logging/setLevel":
		return "SetLoggingLevel"
	case "completion/complete":
		return "Complete"
	case "ping":
		return "Ping"
	default:
		return method
	}
}
