#!/usr/bin/env bash
# Flip the aigw-content-filter container between passthrough and eval
# mode. Runs on the Nutanix host.
#
# Usage:
#     LLM_API_KEY=... ./switch_cf_mode.sh eval
#     ./switch_cf_mode.sh passthrough
set -Eeuo pipefail

MODE="${1:?usage: $0 <passthrough|eval>}"
BUILD_ROOT="${BUILD_ROOT:-/tmp/aigw-deploy}"
CF_CONTAINER="${CF_CONTAINER:-aigw-content-filter}"
CF_IMAGE="${CF_IMAGE:-aigw-content-filter:mcp-content-filter}"
CF_PORT="${CF_PORT:-9093}"

case "$MODE" in
passthrough)
    SRC="${BUILD_ROOT}/content-filter-config.json"
    ;;
eval)
    SRC="${BUILD_ROOT}/content-filter-config.eval.json"
    if [[ -z "${LLM_API_KEY:-}" ]]; then
        echo "ERROR: LLM_API_KEY env var is required for eval mode" >&2
        exit 2
    fi
    ;;
*)
    echo "ERROR: mode must be 'passthrough' or 'eval'" >&2
    exit 2
    ;;
esac

if [[ ! -f "$SRC" ]]; then
    echo "ERROR: config file not found: $SRC" >&2
    exit 2
fi

cp "$SRC" "${BUILD_ROOT}/content-filter-config.active.json"

echo ">>> stopping old content-filter container (if any)"
docker rm -f "$CF_CONTAINER" >/dev/null 2>&1 || true

echo ">>> starting content-filter in '$MODE' mode"
ENV_ARGS=()
if [[ "$MODE" == "eval" ]]; then
    ENV_ARGS+=(-e "LLM_API_KEY=${LLM_API_KEY}")
fi

docker run -d \
    --name "$CF_CONTAINER" \
    --restart unless-stopped \
    -p "${CF_PORT}:${CF_PORT}" \
    -v "${BUILD_ROOT}/content-filter-config.active.json:/etc/content-filter/config.yaml:ro" \
    "${ENV_ARGS[@]}" \
    "$CF_IMAGE" \
    --addr ":${CF_PORT}" --config /etc/content-filter/config.yaml >/dev/null

echo ">>> waiting for /healthz ..."
for i in $(seq 1 20); do
    if curl -fsS -m 2 "http://127.0.0.1:${CF_PORT}/healthz" >/dev/null 2>&1; then
        echo ">>> content-filter healthy in '$MODE' mode"
        docker ps --filter "name=${CF_CONTAINER}" --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
        exit 0
    fi
    sleep 1
done

echo "ERROR: content-filter did not become healthy after 20s" >&2
docker logs --tail 60 "$CF_CONTAINER" >&2 || true
exit 1
