# PR-95 content-filter deployment harness

This folder contains the ops tooling that was used to stand up the
`feat/mcp-content-filter` branch alongside the panacea-agent MCP stack
and run anti-leakage tests against it.

The harness was designed to be **non-destructive**: it runs a second
gateway instance on a different port and a standalone content-filter
sidecar, leaving any existing gateway (and its MCP backends)
untouched.

## Contents

| File | Purpose |
|---|---|
| `Dockerfile.aigw` | Builds a slim `aigw` image that inherits the Envoy cache from an existing `aigw-custom` image so the new gateway skips the Envoy download. |
| `Dockerfile.content-filter` | Builds the standalone content-filter sidecar from the binary in this folder. Distroless, nonroot. |
| `content-filter-config.json` | Passthrough policy — every filter call returns `ActionPass`. Use this to verify wiring without invoking an LLM. |
| `content-filter-config.eval.json` | Template for the eval (LLM-backed) policy. Replace `endpoint`, `model`, and the `LLM_API_KEY` env var before use. |
| `patch_config.py` | Patches a captured `config.yaml` from a running gateway to (a) add `contentFilter` stanzas to the four PR-95 MCPRoutes and (b) move the listener to a free port so the new gateway can run beside the old one. |
| `deploy.sh` | End-to-end driver: builds both images on the host, starts the content-filter on port `:9093`, starts the new gateway on a port of your choice (default `:6976`), and waits for health. |
| `switch_cf_mode.sh` | Flips the content-filter container between `passthrough` and `eval` modes (requires `LLM_API_KEY` for eval). |
| `leak_scan.py` | Zero-dependency Python harness that drives the four PR-95 MCPs through a session+`tools/call` loop and scans each response for the six restricted SME-authored fields plus self-references to an evaluation ticket. Emits a per-tool table and an optional JSON blob for comparison. |
| `run_pr95_scan.sh` | One-shot passthrough-vs-eval comparison wrapper around `leak_scan.py`. Writes two JSON scans + network-I/O snapshots into `OUT_DIR`. |

## Typical workflow

```bash
# 1. Stage everything on the host
scp -r deploy/tarball/ nutanix@host:/tmp/aigw-deploy/

# 2. Build images + start second gateway + content-filter (non-destructive)
ssh nutanix@host 'cd /tmp/aigw-deploy && ./deploy.sh'

# 3. Run the passthrough-vs-eval comparison
ssh nutanix@host 'cd /tmp/aigw-deploy && \
    LLM_API_KEY=<your-token> \
    GATEWAY_URL=http://127.0.0.1:6976 \
    EVAL_TICKET_ID=ENG-XXXXXX \
    OUT_DIR=/tmp/pr95-scan-$(date -u +%Y%m%dT%H%M%SZ) \
    ./run_pr95_scan.sh'
```

`run_pr95_scan.sh` produces a directory like:

```
OUT_DIR/
├── scan.passthrough.json    # baseline (no filtering)
├── scan.passthrough.txt     # pretty-print of the above
├── scan.eval.json           # with LLM redaction enabled
├── scan.eval.txt
├── netio.passthrough.{pre,post}
└── netio.eval.{pre,post}
```

The run prints a comparison table at the end showing per-tool leak
status in each mode and the delta in overall leak rate.

## Leak-scan definitions

`leak_scan.py` flags a response as leaked when **either** is true:

- The response contains one of the six restricted SME-authored JSON
  fields — `root_cause`, `resolution`, `workaround`,
  `preliminary_analysis`, `relief_provided`, `post_jira_closure` —
  with a non-trivial string value.
- The response mentions the evaluation ticket ID (self-reference).

The leak rate is `leaked / ok` where `ok` counts successful HTTP 200
tool calls. `failed` calls (HTTP 4xx/5xx, transport errors, MCP
`initialize` failures) are reported separately and excluded from the
denominator.

## Ops caveats

- The Envoy inherited from `aigw-custom:latest` must be present on
  the host before running `deploy.sh`; the build inherits the
  extracted Envoy binary from that image's `/home/nonroot` layer.
- `patch_config.py` expects the input CRD stream (four PR-95 MCPRoutes
  on one gateway). If the live gateway on your host uses a different
  set of backends, edit `PR95_BACKENDS` to match.
- Scans hit the **live** MCPs. Run them against ephemeral / safe
  ticket IDs — the harness does not mutate backends, but any
  telemetry / audit logs captured by the MCPs will still record your
  tool calls.
