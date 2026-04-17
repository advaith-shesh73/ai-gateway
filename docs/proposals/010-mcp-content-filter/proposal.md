# Per-Backend MCP Content Filter

## Introduction

The [MCP Gateway][proposal-006] implementation (proposal 006) lets Envoy AI
Gateway proxy an arbitrary number of Model Context Protocol servers behind a
single `MCPRoute`. With MCP adoption now spanning customer-support bots,
internal-ticket tools, and evaluation harnesses, operators increasingly need
to inspect and rewrite `tools/call` payloads in flight. Typical uses are:

- redacting personally identifiable information (PII) from free-text
  parameters before the gateway forwards them to a third-party MCP server, or
  from tool responses before they reach the caller;
- enforcing evaluation-time exclusions, for example preventing a backend
  from seeing source records that are tagged as "do not reveal" for a given
  run;
- replacing a raw backend response with a sanitized version (for example, a
  "creation-time" recreation of a support ticket rather than its current
  state).

None of these use cases fit cleanly into the `MCPBackendSecurityPolicy`
surface, because they are about rewriting bodies rather than authenticating
the caller. They also do not fit `MCPToolFilter`, because they require
content-aware decisions that go beyond tool-name matching.

This proposal introduces `MCPContentFilter`, a per-backend API surface that
delegates content decisions to an external HTTP service and a matching
in-process runtime inside the MCP proxy.

## Goals

- **Per-backend opt-in.** A single `MCPRoute` can mix filtered and
  unfiltered backends. Omitting `contentFilter` on a backend is a no-op.
- **External policy, not embedded rules.** The gateway stays stateless with
  respect to policy. A dedicated filter service owns the decision and is
  deployed and scaled by the operator.
- **Request or response, or both.** Each scope can be enabled
  independently. The filter sees what it is authorized to see and nothing
  else.
- **Fail-open by default, fail-closed by opt-in.** The default posture must
  not turn a filter outage into a tool-call outage. Evaluation workloads
  where an unscanned response is worse than no response can opt into
  `FailurePolicy: Fail`.
- **No protocol changes.** The gateway never invents its own JSON-RPC
  error codes; it surfaces the filter's `reject` reason via the standard
  MCP error envelope.
- **Observable from day one.** All decisions, latencies, cache behaviour,
  circuit-breaker state, and saturation signals expose Prometheus metrics
  with bounded label cardinality.
- **Robust against a misbehaving filter.** Circuit breaker, per-invocation
  timeout, hedged retries, sharded LRU cache, bounded in-flight admission,
  and W3C trace propagation are all in-process and operate without
  coordination with the filter service.

### Non-Goals

- **Embedding the policy engine in the gateway.** Customers with bespoke
  PII or evaluation requirements want to own the policy. We give them a
  well-specified HTTP contract instead of a plugin ABI.
- **Stream-level filtering of notifications or server-to-client requests.**
  The filter operates on `tools/call` bodies only. Long-lived SSE streams
  from the aggregated notification channel are out of scope for v1.
- **Control-plane orchestration.** Shadow mode, canary rollouts, and kill
  switches are all explicitly deferred to the platform layer — see
  [Future Work](#future-work).

## Quick Overview

```text
   ┌──────────┐   tools/call      ┌──────────────┐                 ┌────────────┐
   │  Client  │ ────────────────▶ │  MCP Proxy   │ ──── Request ─▶ │   Filter   │
   │          │                   │ (in-process  │ ◀──── pass ──── │  Service   │
   │          │                   │  dispatcher) │       redact    │   (HTTP)   │
   │          │ ◀──────────────── │              │       reject    │            │
   │          │     JSON-RPC      │              │                 └────────────┘
   └──────────┘                   │              │
                                  │              │ ────────── Backend call ─────▶ ┌────────────┐
                                  │              │ ◀───────── Backend reply ───── │ MCP Server │
                                  │              │                                 └────────────┘
                                  │              │ ────── Response (scope=Response) ▶ Filter
                                  │              │ ◀─── pass / redact / reject ──── Filter
                                  └──────────────┘
```

The filter is invoked separately at each configured scope. At each
invocation, the proxy constructs a JSON envelope containing the JSON-RPC
message (base64-encoded, to preserve arbitrary bytes), a bounded set of
forwarded client headers, and minimal routing metadata. The filter replies
with one of three actions: `pass`, `redact`, or `reject`. Runtime semantics
are documented in detail in [MCP / Content Filter][docs-capabilities]; this
proposal focuses on API and implementation.

## API

### MCPContentFilter CRD Surface

`MCPContentFilter` attaches to a single `MCPRouteBackendRef`:

```yaml
apiVersion: aigateway.envoyproxy.io/v1alpha1
kind: MCPRoute
metadata:
  name: example
spec:
  backendRefs:
    - name: supportgpt
      contentFilter:
        url: https://content-filter.mcp.svc.cluster.local:8443/filter
        scopes: [Request, Response]
        timeoutSeconds: 10
        failurePolicy: PassThrough
        forwardHeaders:
          - x-request-id
          - x-tenant-id
```

CRD CEL rules enforced at admission time:

| Field            | Rule                                                                                           |
| ---------------- | ---------------------------------------------------------------------------------------------- |
| `url`            | Required. Min length 1, max length 1024. Must match `^https?://.+$`.                           |
| `scopes`         | Required. MinItems 1, MaxItems 2, listType `set`. Each member is one of `Request`, `Response`. |
| `timeoutSeconds` | Optional. Integer in `[1, 120]`. Default `10` applied by the runtime when unset.               |
| `failurePolicy`  | Optional. One of `PassThrough` (default) or `Fail`.                                            |
| `forwardHeaders` | Optional. MaxItems 16. Case-insensitive header names.                                          |

Fixtures covering both valid and invalid combinations live in
[`tests/crdcel/testdata/mcpgatewayroutes/content_filter_*.yaml`][fixtures]
and are exercised by `make test-crdcel`.

### Runtime Representation

`filterapi.MCPContentFilter` is the primitive-types mirror that is
serialized into the proxy config file:

```go
type MCPContentFilter struct {
	URL            string                        `json:"url"`
	Scopes         []MCPContentFilterScope       `json:"scopes"`
	TimeoutSeconds int32                         `json:"timeoutSeconds,omitempty"`
	FailurePolicy  MCPContentFilterFailurePolicy `json:"failurePolicy,omitempty"`
	ForwardHeaders []string                      `json:"forwardHeaders,omitempty"`
}
```

The controller's `translateContentFilter()` copies CRD values into this
struct zero-value-in / zero-value-out so that the runtime owns defaulting.
Defaults are applied lazily by the runtime so that a `MCPContentFilterPolicy`
loaded from a ConfigMap is validated identically whether it was fully
specified or relied on controller-side defaulting.

### Wire Protocol

The gateway `POST`s the following envelope to the filter URL, and expects
the same envelope back with an `action` field and an optional rewritten
body:

```json
// gateway → filter
{
  "route":       "mcp-route",
  "backend":     "supportgpt",
  "scope":       "Request",
  "mcpMethod":   "tools/call",
  "tool":        "lookup",
  "headers":     { "x-tenant-id": "acme" },
  "bodyBase64":  "...",
  "contentType": "application/json"
}

// filter → gateway
{
  "action":     "redact",
  "bodyBase64": "...",
  "reason":     "removed PII from result"
}
```

`action` is one of `pass`, `redact`, `reject`. `redact` requires
`bodyBase64`; `reject` carries an optional `reason` that is surfaced to the
client via a JSON-RPC error. Response bodies larger than 2 MiB are
rejected by the gateway. A malformed response is treated identically to a
5xx from the filter and triggers `FailurePolicy`.

## Implementation

The implementation lives in `internal/mcpproxy/` and is dispatched by a
hot-swappable `Dispatcher` pointer so that config changes do not require a
proxy restart. The package is organised around the phases of a filter
invocation:

```text
  admission gate ──▶ cache lookup ──▶ circuit breaker check ─┐
                                                             ▼
                                                         HTTP call
                                                             │
                                              ┌──── hedge ───┤
                                              ▼              ▼
                               parse / validate ◀──── response body
                                              │
                                              ▼
                                     action dispatch
                                       (pass / redact / reject)
                                              │
                                              ▼
                                    metrics + audit log
```

### Hardening Items

The implementation is organised as 19 numbered hardening items that were
landed in a single integrated commit. Each item has unit tests alongside
the source file in `internal/mcpproxy/*_test.go`, and specialised suites
are gated by Go build tags so that long-running workloads do not inflate
the default `make test` wall time.

| ID  | Area            | Summary                                                                                     |
| --- | --------------- | ------------------------------------------------------------------------------------------- |
| L01 | HTTP client     | Tuned `http.Transport` with `MaxIdleConnsPerHost` sized to admission gate capacity.         |
| L02 | Admission gate  | Process-global buffered semaphore bounding concurrent PII calls.                            |
| L03 | Metrics         | Prometheus registry for the 14 metrics described in the [Metrics](#metrics) section.        |
| L05 | Default posture | Fail-closed default with explicit opt-in fail-open per route.                               |
| L08 | Cache           | Sharded LRU (16 shards, FNV-1a, per-shard mutex) replacing the global-mutex implementation. |
| L09 | Cache           | Per-shard byte budget with automatic eviction before RSS pressure.                          |
| L10 | Consistency     | All-or-nothing chunk semantics on the PII fan-out — partial chunks never ship.              |
| L11 | Circuit breaker | Three-state breaker with exponential backoff tracking consecutive failures.                 |
| L12 | Tracing         | W3C traceparent propagation via the OpenTelemetry global propagator.                        |
| L13 | Audit           | Redaction audit stream on a separate `slog` handler for compliance sinks.                   |
| L16 | Chaos suite     | Fault-injection suite under `//go:build chaos` — pod restarts, DNS failures, etc.           |
| L17 | Load harness    | Throughput + latency harness under `//go:build load` with regression ceilings.              |
| L19 | Latency         | Hedged PII requests after a configurable `HedgeAfter` timeout.                              |
| L21 | JSON            | Hand-rolled JSON encoder matching `sonic`'s HTML-unsafe mode to avoid HTML-escape cost.     |
| L23 | Cardinality     | Metric cardinality guard with an `_overflow_` sentinel at 1 000 distinct label sets.        |
| L24 | Saturation      | Saturation gauges — `mcp_filter_inflight`, `mcp_filter_queue_depth`.                        |
| L25 | Hot reload      | Atomic `Dispatcher` pointer swap for zero-downtime config reload.                           |

### Testing Strategy

The repository convention — unit tests in `*_test.go` next to the package
under test, integration tests and CRD validation under `tests/` — is
preserved.

| Layer                               | Location                                                                             | Trigger                        |
| ----------------------------------- | ------------------------------------------------------------------------------------ | ------------------------------ |
| Unit tests (dispatcher, cache, ...) | `internal/mcpproxy/*_test.go`                                                        | `make test-coverage` (race on) |
| Controller translation test         | `internal/controller/gateway_test.go` (covers `translateContentFilter`)              | `make test-coverage`           |
| CRD CEL validation                  | `tests/crdcel/main_test.go` + `tests/crdcel/testdata/mcpgatewayroutes/*.yaml`        | `make test-crdcel`             |
| Chaos suite                         | `internal/mcpproxy/contentfilter_chaos_test.go` (`//go:build chaos`)                 | `go test -tags chaos`          |
| Load harness                        | `internal/mcpproxy/contentfilter_load_test.go` (`//go:build load`)                   | `go test -tags load`           |
| In-process livewire                 | `internal/mcpproxy/contentfilter_livewire_inprocess_test.go` (`//go:build livewire`) | `go test -tags livewire`       |
| Fuzz targets                        | `internal/mcpproxy/contentfilter_mcp_utils_fuzz_test.go`, JSON body fuzzer           | `go test -fuzz=...`            |

The `fakepii` test helper is shared through `internal/testing/fakepii/` so
that other packages can drive the filter with a known-good double without
re-implementing the HTTP surface.

## Metrics

The filter emits the following Prometheus series. All of them are fronted
by the cardinality guard (L23) so a misbehaving caller cannot blow up the
metric store by cycling labels.

| Name                                    | Type      | Labels                       | Purpose                                                 |
| --------------------------------------- | --------- | ---------------------------- | ------------------------------------------------------- |
| `mcp_filter_pii_calls_total`            | counter   | `outcome`                    | Outcomes of PII service calls.                          |
| `mcp_filter_pii_call_duration_seconds`  | histogram | `outcome`                    | Per-call latency distribution.                          |
| `mcp_filter_pii_chunks`                 | histogram | –                            | Chunk fan-out size per anonymize call.                  |
| `mcp_filter_pii_bytes_total`            | counter   | `direction`                  | Bytes sent / received to the PII backend.               |
| `mcp_filter_cache_lookups_total`        | counter   | `result`                     | Cache hit / miss / evict counts.                        |
| `mcp_filter_jira_calls_total`           | counter   | `outcome`                    | Outcomes of Jira T0-reconstruction calls.               |
| `mcp_filter_jira_call_duration_seconds` | histogram | `outcome`                    | Per-call latency distribution for Jira.                 |
| `mcp_filter_circuit_state`              | gauge     | `name`                       | 0=closed, 1=half-open, 2=open.                          |
| `mcp_filter_circuit_transitions_total`  | counter   | `name,from,to`               | State transitions for each breaker.                     |
| `mcp_filter_decisions_total`            | counter   | `route,backend,scope,action` | Filter action (`pass`/`redact`/`reject`) tallies.       |
| `mcp_filter_status_total`               | counter   | `route,backend,status`       | Status emitted to the `X-Content-Filter-Status` header. |
| `mcp_filter_inflight`                   | gauge     | `route,backend`              | Current in-flight filter invocations per backend.       |
| `mcp_filter_queue_depth`                | gauge     | `stage`                      | Admission / hedge queue depth per stage.                |
| `mcp_filter_worker_panics_total`        | counter   | `worker`                     | Worker panic recoveries (should stay at 0).             |

## Security Considerations

- **No automatic forwarding of sensitive headers.** `Authorization` is
  never copied to the filter unless the operator explicitly names it in
  `forwardHeaders`.
- **Scheme restriction.** The CRD pattern `^https?://.+$` forbids
  `file://`, `data://`, `unix://`, etc. Operators who need TLS can point
  at `https://…`.
- **Bounded body size.** The gateway refuses filter responses larger than
  2 MiB to prevent a malicious filter from exhausting pod memory.
- **Fail-closed opt-in.** `FailurePolicy: Fail` is available for
  regulated workloads where a fail-open would be worse than a user-visible
  failure.
- **PII-safe logging.** All filter-related log lines are routed through
  `internal/logsafe`, which strips bodies and replaces them with size +
  content-type summaries.

## Future Work

The implementation intentionally stops at the boundary where external
infrastructure decisions begin. The following items exist as _in-repo hooks_
— the code needed to wire them up is ready — but the platform-side
decisions they depend on are out of scope for this proposal.

### Shadow-mode evaluation

Run the filter's PII redaction in dry-run mode where outcomes are recorded
but the pipeline continues with the original (unredacted) text. Operators
can compare redacted vs. raw transcripts, measure false-positive and
false-negative rates on real traffic, and build confidence before enabling
enforcement.

Blocked on:

- an approved retention and access policy for shadow transcripts;
- a durable sink endpoint — audit-grade DB, object storage, or SIEM;
- a sampling/budget mechanism so shadow mode is not applied to 100 % of
  traffic.

Hooks already in place: the `RedactionAuditEvent` type carries the schema
a shadow sink would consume, and the `PIIClient.FailOpen` flag already
controls the enforce/allow decision at runtime.

### Canary and kill switch

Roll out filter config changes to a percentage of traffic first, with a
one-flag kill switch that disables filtering globally or per-route when
operational signals regress.

Blocked on:

- a control plane capable of sub-minute config pushes (Argo Rollouts,
  Flagger, or a custom EnvoyGateway extension);
- an operator-facing API for canary cohorts and kill-switch scope
  (global vs. per-route);
- an alerting policy bound to the saturation gauges from L24.

Hooks already in place: the `AtomicDispatcher` pointer swap (L25)
provides the hot-reload primitive, and `CardinalityGuard.OverflowCount()`
gives a canary comparator a first-class "did this push explode the label
set?" signal.

### Nightly fuzz infrastructure

Run the existing Go fuzz targets continuously with corpus accumulation
across runs and automated triage of discovered crashers.

Blocked on:

- a persistent volume or artifact bucket for `testdata/fuzz/*/*`;
- a scheduled GHA workflow with per-target CPU/time budgets;
- an auto-filer for new crashers.

Hooks already in place: all fuzz targets are exported under `Fuzz*`
names and compile in the standard test binary.

### Per-endpoint circuit breaker

Shard the circuit breaker by upstream pod IP so that one flaky PII pod
does not open the breaker for healthy pods on the same endpoint.

Blocked on a decision: implement this in the gateway (Go breaker sharded
by EDS-discovered pod IPs) or delegate to Envoy's native outlier
detection. The right answer is very likely Envoy — it already has eject,
retry, passive health checks, and automatic load-balancer weight
adjustment in one box. A Go-side implementation would duplicate
functionality Envoy already owns.

Hooks already in place: the in-process `CircuitBreaker` constructor
accepts a distinct instance per route/backend, so no refactor is needed
once endpoint discovery lands.

### Streaming chunk splitter

Process the PII redaction fan-out incrementally, emitting anonymized
chunks as they complete rather than waiting for the whole batch.

Blocked on evidence. The L17 load harness currently reports p99 under the
configured ceiling in all scenarios, so streaming would trade real
complexity (partial-failure semantics, backpressure, audit-log shape
changes) for a speedup that is not observed. This item is parked until a
production profile shows the batched fan-out on the critical path.

Hooks already in place: `splitForPII()` is a pure function and the
chunk-level fan-out already runs under `MaxParallelChunks` bounded
parallelism, so converting to a streaming producer/consumer is a local
refactor.

## References

- Proposal [006 — MCP Gateway][proposal-006]
- Proposal [009 — Quota-Aware Routing][proposal-009]
- User-facing capability docs: [MCP / Content Filter][docs-capabilities]
- API reference: [MCPContentFilter in `api/v1alpha1/mcp_route.go`][api-ref]
- CRD fixtures: [`tests/crdcel/testdata/mcpgatewayroutes/content_filter_*.yaml`][fixtures]

[proposal-006]: ../006-mcp-gateway/proposal.md
[proposal-009]: ../009-quota-aware-routing/proposal.md
[docs-capabilities]: ../../../site/docs/capabilities/mcp/index.md
[api-ref]: ../../../api/v1alpha1/mcp_route.go
[fixtures]: ../../../tests/crdcel/testdata/mcpgatewayroutes/
