#!/usr/bin/env python3
"""Patch config.yaml: add contentFilter to the PR-95 MCPRoutes.

Reads the existing config.yaml as a stream of YAML documents, locates the
MCPRoute resources whose metadata.name is one of the PR-95 targets, and
attaches a contentFilter block to each backendRef that does not already
have one. Preserves all other documents verbatim.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml


PR95_ROUTES = {
    "supportgpt-route",
    "nurag-route",
    "glean-route",
    "atlassian-route",
}

CONTENT_FILTER_BLOCK = {
    "enabled": True,
    # The new gateway runs on the docker bridge network in its own netns
    # (so it doesn't collide with the old gateway's host-network internal
    # ports). Content-filter is reachable via the host-published port on
    # the bridge gateway IP, same pattern as the MCP backends.
    "url": "http://172.17.0.1:9093/filter",
    "scopes": ["Request", "Response"],
    "timeoutSeconds": 30,
    "failurePolicy": "PassThrough",
    "forwardHeaders": [
        "X-Eval-Ticket-Id",
        "X-Request-Id",
    ],
}

NEW_LISTENER_PORT = 6976


def patch(src: Path, dst: Path) -> None:
    raw = src.read_text()
    docs = list(yaml.safe_load_all(raw))
    patched_refs = 0
    patched_listener = False
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind")
        if kind == "MCPRoute":
            name = doc.get("metadata", {}).get("name", "")
            if name not in PR95_ROUTES:
                continue
            refs = doc.get("spec", {}).get("backendRefs", [])
            for ref in refs:
                if "contentFilter" in ref:
                    continue
                ref["contentFilter"] = CONTENT_FILTER_BLOCK.copy()
                patched_refs += 1
        elif kind == "Gateway":
            listeners = doc.get("spec", {}).get("listeners", []) or []
            for listener in listeners:
                if listener.get("port") == 6975:
                    listener["port"] = NEW_LISTENER_PORT
                    patched_listener = True

    out = "\n".join(
        "---\n" + yaml.safe_dump(d, default_flow_style=False, sort_keys=False)
        for d in docs
        if d is not None
    )
    dst.write_text(out)
    print(
        f"patched {patched_refs} backendRef contentFilter stanzas; "
        f"listener_port_6975->{NEW_LISTENER_PORT}={patched_listener} -> {dst}"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: patch_config.py <in.yaml> <out.yaml>", file=sys.stderr)
        sys.exit(2)
    patch(Path(sys.argv[1]), Path(sys.argv[2]))
