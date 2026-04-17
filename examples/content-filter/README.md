# MCP Content Filter — Eval Policy example

These manifests show how to run the out-of-process **content-filter**
service together with an `MCPRoute` that consults it via the
`contentFilter` field, deploying panacea-agent
[PR 95](https://github.com/nutanix-core/panacea-agent/pull/95)
(evaluation-mode semantic redaction) as a standalone service inside
the Envoy AI Gateway.

## What the content-filter service does

The content-filter service is a stateless HTTP service that terminates
the wire contract defined in
[`internal/contentfilter/wire/envelope.go`](../../internal/contentfilter/wire/envelope.go).
It accepts `POST /filter` envelopes carrying base64-encoded MCP bodies,
dispatches them to a pluggable `Policy`, and returns a verdict
(`pass`, `redact`, `reject`). It also exposes `GET /healthz` for k8s
probes.

The first policy we ship is **`eval`** — the Go port of PR 95's
LLM-powered redactor. For each response-scope `tools/call` invocation,
it:

1. Base64-decodes the JSON-RPC envelope forwarded by the gateway.
2. Extracts the tool output, unwrapping the MCP `content` wrapper if
   present (preserves extra fields byte-for-byte).
3. Issues a single-turn chat completion against an OpenAI-compatible
   endpoint (default: `https://hkn12.ai.nutanix.com/enterpriseai/v1/chat/completions`,
   default model: `hack-reason`) with the PR 95 prompts.
4. Strips `<think>` blocks and markdown fences from the LLM response,
   rebuilds the MCP wrapper, and returns the redacted body to the
   gateway.
5. If the LLM is unreachable or returns non-JSON, falls back to a
   hard-coded safe redaction (`[ENTIRE OUTPUT REDACTED - FILTER
UNAVAILABLE]`) — over-filtering is always preferred to data leakage.

## Files in this directory

| File                             | Purpose                                                                                                 |
| -------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `content-filter-deployment.yaml` | Deploys the content-filter service (Deployment, Service, ConfigMap, Secret, ServiceAccount, Namespace). |
| `gateway-route-shadow.yaml`      | Example `MCPRoute` wiring the filter into a Jira backend in **shadow mode** with 10% sampling.          |
| `gateway-route-enforce.yaml`     | Same `MCPRoute` flipped to **enforce mode** with `failurePolicy: Fail`.                                 |
| `global-kill-switch.yaml`        | Example `MCPContentFilterPolicy` ConfigMap for the cluster-wide `globalDisable` knob.                   |

## Rollout recipe

The three knobs that matter during rollout are:

1. **`mode`** (on the `MCPContentFilter` spec) — `Shadow` observes,
   `Enforce` applies the verdict.
2. **`shadowSampleRatePermille`** (in permille, 0..1000) — caps LLM
   cost during shadow rollout. Ignored in enforce mode.
3. **`enabled`** (per-backend) and **`globalDisable`** (cluster-wide)
   — two kill switches, no gateway restart needed.

### Step 1 — Deploy the service

```bash
# Adjust the registry + tag to yours, then:
kubectl apply -f content-filter-deployment.yaml
kubectl -n content-filter rollout status deploy/content-filter --timeout=90s
```

Set the LLM bearer token in the `content-filter-llm-credentials`
Secret before traffic starts flowing. Without a token the policy
returns safe-redaction for every filtered call (useful for smoke
tests; useless in production).

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
- `mcp_filter_decisions_total{action="shadow_would_redact"}` — LLM
  rewrote the body.
- `mcp_filter_decisions_total{action="shadow_would_reject"}` — policy
  chose to reject.
- `mcp_filter_decisions_total{action="shadow_sampled_out"}` — call was
  NOT sent to the filter (below the sample-rate budget).
- `mcp_filter_decisions_total{action="shadow_would_fail"}` — upstream
  filter errored; would have fallen back per FailurePolicy.

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
kubectl -n envoy-gateway-system patch configmap mcp-content-filter-policy \
  --type merge \
  -p '{"data":{"policy.json":"{\"globalDisable\": true, ...}"}}'
```

(For a targeted rollback, flip the per-backend `enabled: false`
instead — that's a single `kubectl edit mcproute` and only affects
one backend.)

## Customising the filter policy

The content-filter ConfigMap in `content-filter-deployment.yaml`
carries the PR 95 defaults verbatim. The common knobs:

| Field                        | Purpose                                                         | Default                                                                         |
| ---------------------------- | --------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `eval.endpoint`              | OpenAI-compatible chat/completions URL.                         | `https://hkn12.ai.nutanix.com/enterpriseai/v1/chat/completions` (PR 95 default) |
| `eval.model`                 | Model name in the request payload.                              | `"hack-reason"`                                                                 |
| `eval.apiKeyEnv`             | Env var to read the bearer token from.                          | `"LLM_API_KEY"`                                                                 |
| `eval.apiKeyFile`            | Alternative file-mount path for the bearer token.               | `""`                                                                            |
| `eval.timeoutSeconds`        | Per-call LLM timeout (seconds).                                 | `60`                                                                            |
| `eval.temperature`           | Sampling temperature (keep at 0 for determinism).               | `0`                                                                             |
| `eval.insecureSkipTLSVerify` | Skip TLS verify (matches PR 95 for internal endpoints).         | `false`                                                                         |
| `eval.filteredTools`         | Allowlist of tool names to actually LLM-filter.                 | `[]` (=passthrough)                                                             |
| `eval.evalTicketID`          | Default evaluation ticket ID (replaceable per-call via header). | `""`                                                                            |
| `eval.ticketHeader`          | Header name for per-call ticket override.                       | `"X-Eval-Ticket-Id"`                                                            |

Per-call ticket ID: the gateway forwards the header listed in the
`MCPContentFilter.forwardHeaders` list to the filter. If it matches
`eval.ticketHeader`, that value wins over `eval.evalTicketID` —
this lets one filter pod serve many concurrent evaluation runs
without a restart.
