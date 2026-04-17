#!/usr/bin/env bash
# Deploy new aigw (with PR #1 content-filter wiring) and the
# standalone content-filter service on the Nutanix 'bigbang' box.
#
# The existing aigw-mcp-gateway on :6975 is left untouched.
# The new build runs as 'aigw-mcp-gateway-cf' on :6976 with its own
# config that wires contentFilter into the PR-95 MCPRoutes.
#
# Both gateway containers run in host network mode, matching the
# existing deployment.

set -Eeuo pipefail

BUILD_ROOT="${BUILD_ROOT:-/tmp/aigw-deploy}"
AIGW_TAG="aigw-custom:mcp-content-filter"
CF_TAG="aigw-content-filter:mcp-content-filter"
OLD_GATEWAY_CONTAINER="aigw-mcp-gateway"
NEW_GATEWAY_CONTAINER="aigw-mcp-gateway-cf"
CF_CONTAINER="aigw-content-filter"
CONFIG_DIR="/home/nutanix/Desktop/mohit/aigw-gateway"
NEW_CONFIG_FILE="${CONFIG_DIR}/config.cf.yaml"
NEW_GATEWAY_PORT="${NEW_GATEWAY_PORT:-6976}"
NEW_ADMIN_PORT="${NEW_ADMIN_PORT:-6065}"
CF_PORT="${CF_PORT:-9093}"

echo "==> staging: ${BUILD_ROOT}"
cd "${BUILD_ROOT}"

echo "==> capturing environment from existing ${OLD_GATEWAY_CONTAINER}"
OLD_ENV_FILE="${BUILD_ROOT}/old-gateway.env"
if docker inspect "${OLD_GATEWAY_CONTAINER}" >/dev/null 2>&1; then
    docker inspect \
        --format '{{range .Config.Env}}{{println .}}{{end}}' \
        "${OLD_GATEWAY_CONTAINER}" \
        | grep -E '^(SOURCEGRAPH_TOKEN|GLEAN_API_TOKEN|AIGW_|LLM_API_KEY|LOG_LEVEL|OPENAI_API_KEY)=' \
        > "${OLD_ENV_FILE}" || true
    echo "    captured $(wc -l <"${OLD_ENV_FILE}") env vars"
else
    echo "    old gateway not present; new container will start with only LLM_API_KEY from the shell environment (if any)"
    : > "${OLD_ENV_FILE}"
fi

# Make sure LLM_API_KEY (if exported in this shell) ends up in the env file.
if [[ -n "${LLM_API_KEY:-}" ]] && ! grep -q '^LLM_API_KEY=' "${OLD_ENV_FILE}"; then
    echo "LLM_API_KEY=${LLM_API_KEY}" >> "${OLD_ENV_FILE}"
    echo "    injected LLM_API_KEY from current shell into env file"
fi

echo "==> installing patched config as ${NEW_CONFIG_FILE}"
cp config.yaml.new "${NEW_CONFIG_FILE}"

echo "==> installing content-filter config (under ${BUILD_ROOT}, no sudo needed)"
CF_CONFIG_HOST="${BUILD_ROOT}/content-filter-config.active.json"
cp content-filter-config.json "${CF_CONFIG_HOST}"

echo "==> building ${AIGW_TAG}"
docker build -t "${AIGW_TAG}" -f Dockerfile.aigw .

echo "==> building ${CF_TAG}"
docker build -t "${CF_TAG}" -f Dockerfile.content-filter .

echo "==> (re)starting content-filter container (bridge + port ${CF_PORT})"
docker rm -f "${CF_CONTAINER}" 2>/dev/null || true
docker run -d \
    --name "${CF_CONTAINER}" \
    --restart unless-stopped \
    --network bridge \
    -p "${CF_PORT}:${CF_PORT}" \
    -v "${CF_CONFIG_HOST}:/etc/content-filter/config.json:ro" \
    "${CF_TAG}" \
    --addr ":${CF_PORT}" --config /etc/content-filter/config.json --log-level info

echo "==> waiting for content-filter to become healthy on :${CF_PORT}"
for i in {1..15}; do
    if curl -fsS "http://127.0.0.1:${CF_PORT}/healthz" >/dev/null 2>&1; then
        echo "    content-filter OK after ${i}s"
        break
    fi
    sleep 1
done

echo "==> (re)starting new gateway container (${NEW_GATEWAY_CONTAINER}) on :${NEW_GATEWAY_PORT} (bridge netns to avoid port conflicts with old gateway)"
docker rm -f "${NEW_GATEWAY_CONTAINER}" 2>/dev/null || true

ENV_ARGS=()
if [[ -s "${OLD_ENV_FILE}" ]]; then
    ENV_ARGS+=(--env-file "${OLD_ENV_FILE}")
fi

docker run -d \
    --name "${NEW_GATEWAY_CONTAINER}" \
    --restart unless-stopped \
    --network bridge \
    -p "${NEW_GATEWAY_PORT}:${NEW_GATEWAY_PORT}" \
    -v "${NEW_CONFIG_FILE}:/etc/aigw/config.yaml:ro" \
    "${ENV_ARGS[@]}" \
    "${AIGW_TAG}" \
    run /etc/aigw/config.yaml --admin-port "${NEW_ADMIN_PORT}" --debug

echo "==> waiting for new gateway to come up on :${NEW_GATEWAY_PORT}"
for i in {1..60}; do
    if curl -fsS "http://127.0.0.1:${NEW_GATEWAY_PORT}/mcp" >/dev/null 2>&1 \
    || curl -fsS "http://127.0.0.1:${NEW_ADMIN_PORT}/" >/dev/null 2>&1 \
    || docker logs --tail 50 "${NEW_GATEWAY_CONTAINER}" 2>&1 | grep -qiE "listening|admin server|envoy .*started|ready"; then
        echo "    gateway responded / log indicates startup after ${i}s"
        break
    fi
    sleep 1
done

echo "==> final status"
docker ps --filter name="${OLD_GATEWAY_CONTAINER}" \
          --filter name="${NEW_GATEWAY_CONTAINER}" \
          --filter name="${CF_CONTAINER}" \
    --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"

echo
echo "New gateway on :${NEW_GATEWAY_PORT}, admin :${NEW_ADMIN_PORT}."
echo "Content-filter on :${CF_PORT}."
echo "Old gateway on :6975 is untouched."
echo
echo "Smoke test:"
echo "  curl -s http://127.0.0.1:${CF_PORT}/healthz && echo OK"
echo "  curl -s -X POST -H 'Content-Type: application/json' \\"
echo "       -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}' \\"
echo "       http://127.0.0.1:${NEW_GATEWAY_PORT}/mcp/supportgpt"
echo
echo "Rollback (tear down new only):"
echo "  docker stop ${NEW_GATEWAY_CONTAINER} ${CF_CONTAINER}"
echo "  docker rm   ${NEW_GATEWAY_CONTAINER} ${CF_CONTAINER}"
