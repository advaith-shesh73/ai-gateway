#!/usr/bin/env bash
# Single-command PR-95 leak comparison: passthrough vs eval.
# Runs on the Nutanix host.
set -Eeuo pipefail

BUILD_ROOT="${BUILD_ROOT:-/tmp/aigw-deploy}"
GATEWAY_URL="${GATEWAY_URL:-http://127.0.0.1:6976}"
EVAL_TICKET_ID="${EVAL_TICKET_ID:-ENG-912818}"
LLM_API_KEY="${LLM_API_KEY:?LLM_API_KEY env var is required}"
OUT_DIR="${OUT_DIR:-/tmp/pr95-scan-$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$OUT_DIR"
cd "$BUILD_ROOT"

net_stats() {
    docker stats --no-stream --format '{{.Name}} NetI/O: {{.NetIO}} Mem: {{.MemUsage}}' aigw-content-filter aigw-mcp-gateway-cf 2>/dev/null || true
}

run_scan() {
    local label="$1"
    local json_out="${OUT_DIR}/scan.${label}.json"
    local txt_out="${OUT_DIR}/scan.${label}.txt"
    echo
    echo "=========================================================="
    echo "[$(date -u +%H:%M:%SZ)] Running leak scan in '${label}' mode"
    echo "=========================================================="
    echo "--- net I/O before scan ---"
    net_stats | tee "${OUT_DIR}/netio.${label}.pre"
    # leak_scan.py returns 1 when any leak is detected; that's a
    # legitimate result for passthrough and we don't want it to
    # abort the comparison run. Capture the exit code via PIPESTATUS
    # but do not propagate it.
    set +e
    GATEWAY_URL="$GATEWAY_URL" EVAL_TICKET_ID="$EVAL_TICKET_ID" \
        SCAN_MODE_LABEL="$label" SCAN_JSON_OUT="$json_out" \
        python3 /tmp/leak_scan.py | tee "$txt_out"
    set -e
    echo "--- net I/O after scan ---"
    net_stats | tee "${OUT_DIR}/netio.${label}.post"
}

echo ">>> flipping content-filter to passthrough"
./switch_cf_mode.sh passthrough
sleep 2
run_scan passthrough

echo
echo ">>> flipping content-filter to eval"
LLM_API_KEY="$LLM_API_KEY" ./switch_cf_mode.sh eval
sleep 2
run_scan eval

echo
echo "=========================================================="
echo "[$(date -u +%H:%M:%SZ)] Comparison summary"
echo "=========================================================="
python3 - "$OUT_DIR" <<'PY'
import json, sys, pathlib
d = pathlib.Path(sys.argv[1])
pt = json.loads((d / "scan.passthrough.json").read_text())
ev = json.loads((d / "scan.eval.json").read_text())

def rate(x):
    return f"{x['leak_rate']:.1%}"

print(f"eval_ticket            = {pt['eval_ticket']}")
print(f"passthrough leak_rate  = {rate(pt)}   ({pt['leaked']}/{pt['ok']} ok calls)")
print(f"eval        leak_rate  = {rate(ev)}   ({ev['leaked']}/{ev['ok']} ok calls)")

delta = pt['leak_rate'] - ev['leak_rate']
print(f"delta                  = {delta:+.1%}   (reduction when eval is on)")
print()
print(f"{'route':<18} {'tool':<36} {'passthrough':>12} {'eval':>8}")
print("-" * 80)

pt_by = {(r['route'], r['tool']): r for r in pt['results']}
ev_by = {(r['route'], r['tool']): r for r in ev['results']}
for key in pt_by:
    p = pt_by[key]
    e = ev_by.get(key, {})
    p_mark = "LEAK" if p['leaked'] else "    "
    e_mark = "LEAK" if e.get('leaked') else "    "
    print(f"{p['route']:<18} {p['tool']:<36} {p_mark:>12} {e_mark:>8}")
PY

echo
echo "All artifacts under: $OUT_DIR"
ls -la "$OUT_DIR"
