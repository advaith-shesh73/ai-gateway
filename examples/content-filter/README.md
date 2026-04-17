# MCP Content Filter — Gateway integration example

These manifests show how to wire an `MCPRoute` into an **external**
content-filter HTTP service via the `contentFilter` field on a
backend. The gateway itself ships no filter implementation — it
simply POSTs the request/response body to a filter endpoint and
applies the verdict (`pass`, `redact`, `reject`).

## Where the filter service lives

The reference implementation of the filter service (PR 95 evaluation
policy — LLM-powered semantic redaction) is maintained in
[panacea-agent](https://github.com/nutanix-core/panacea-agent)
under `services/aigw-content-filter-dispatcher/`. Deploy that
service independently (Helm chart in the same repo) and point these
gateway manifests at its `Service` address.

From the gateway's point of view the filter is just another HTTP
backend speaking a tiny JSON envelope:

- `POST /v1/filter`
- Request body: `{"scope":"request|response","tool":"...","bodyBase64":"..."}`
- Response body: `{"action":"pass|redact|reject","bodyBase64":"...","reason":"..."}`

Any service implementing that contract is acceptable — the evaluation
policy in panacea-agent is one reference implementation, not the only
one.

## Files in this directory

| File                             | Purpose                                                                                                 |
| -------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `gateway-route-shadow.yaml`      | Example `MCPRoute` wiring the filter into a Jira backend in **shadow mode** with 10% sampling.          |
| `gateway-route-enforce.yaml`     | Same `MCPRoute` flipped to **enforce mode** with `failurePolicy: Fail`.                                 |
| `global-kill-switch.yaml`        | Example `MCPContentFilterPolicy` ConfigMap for the cluster-wide `globalDisable` knob.                   |

## Rollout recipe

The three knobs that matter during rollout are:

1. **`mode`** (on the `MCPContentFilter` spec) — `Shadow` observes,
   `Enforce` applies the verdict.
2. **`shadowSampleRatePermille`** (in permille, 0..1000) — caps
   filter-service cost during shadow rollout. Ignored in enforce
   mode.
3. **`enabled`** (per-backend) and **`globalDisable`** (cluster-wide)
   — two kill switches, no gateway restart needed.

### Step 1 — Deploy the filter service

See the [panacea-agent
documentation](https://github.com/nutanix-core/panacea-agent/tree/main/services/aigw-content-filter-dispatcher)
for how to deploy the external filter service. Make a note of the
Kubernetes `Service` DNS name (e.g.
`aigw-content-filter.panacea.svc.cluster.local:8080`) — you'll
reference it in the `MCPRoute` backend config below.

A few deployment checks worth confirming on the filter Pod:

- **Set an explicit `terminationGracePeriodSeconds`** on the filter
  Pod equal to *at least* the longest `timeoutSeconds` you configure
  on any `MCPContentFilter` pointing at it, plus a small buffer
  (e.g. +5s) to cover connection draining. Without this, rolling
  the filter during peak traffic can cause in-flight filter calls
  to be cut short and trip gateway-side `failurePolicy`.
- Expose `/healthz` and `/readyz` on the filter container and wire
  them into Pod readiness/liveness probes. The gateway only uses
  them transitively (via Service endpoint selection), but they are
  what lets Kubernetes roll the Deployment without sending traffic
  to a half-initialised pod.
- Run with a realistic `replicaCount` and `PodDisruptionBudget` so
  that a node drain cannot take down the last replica — otherwise a
  routine maintenance window flips the gateway into `failed-open`
  (or worse, `unavailable` + `Fail`) for every filtered backend.

### Step 2 — Shadow rollout (measure)

```bash
kubectl apply -f gateway-route-shadow.yaml
```

Watch:

```bash
kubectl -n envoy-gateway-system logs -l app.kubernetes.io/name=envoy-ai-gateway -f \
  | grep -E 'mcp_filter_decisions_total|X-Content-Filter-Status'
```

Key metrics (exposed on the gateway's Prometheus endpoint):

- `mcp_filter_decisions_total{action="shadow_would_pass"}` — tool
  output was clean.
- `mcp_filter_decisions_total{action="shadow_would_redact"}` —
  filter rewrote the body.
- `mcp_filter_decisions_total{action="shadow_would_reject"}` —
  filter chose to reject.
- `mcp_filter_decisions_total{action="shadow_sampled_out"}` — call
  was NOT sent to the filter (below the sample-rate budget).
- `mcp_filter_decisions_total{action="shadow_would_fail"}` —
  upstream filter errored; would have fallen back per FailurePolicy.

Hold in shadow mode until the rate of `would_redact` and
`would_reject` decisions stabilises and matches the expected
business-impact profile.

### Step 3 — Enforce cutover

```bash
kubectl apply -f gateway-route-enforce.yaml
```

Note the `failurePolicy: Fail` on the enforce manifest — for
evaluation workloads, "filter is down" must translate to "tool call
fails" rather than "tool call silently returns unscanned content".

### Step 4 — Hot rollback

If anything regresses, the fastest rollback path is the cluster-wide
kill switch:

```bash
kubectl apply -f global-kill-switch.yaml
```

(For a targeted rollback, flip the per-backend `enabled: false`
instead — that's a single `kubectl edit mcproute` and only affects
one backend.)

## Tuning the filter's behaviour

All filter-side knobs (LLM endpoint, model, filtered tool allowlist,
timeout, ticket-header name, etc.) now live with the external
service — see `services/aigw-content-filter-dispatcher/` in
panacea-agent. The gateway only controls **when** the filter is
invoked (shadow vs enforce, sample rate, kill switches) and **how**
it reacts to verdicts — it does not understand the filter's
internals.
