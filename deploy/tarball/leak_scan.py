#!/usr/bin/env python3
"""Leak scanner for PR-95 anti-leakage testing against a live aigw.

Drives the 4 problematic MCPs from PR 95 through the gateway, scans
responses for the restricted fields that SMEs author (root_cause,
resolution, workaround, preliminary_analysis, relief_provided,
post_jira_closure) and for self-references to the evaluation ticket
ID, then prints a per-route / per-tool leak rate.

This is deliberately zero-dependency (stdlib only) so it can run on
the Nutanix 'bigbang' box without pip.

Usage:
    GATEWAY_URL=http://127.0.0.1:6976 \
    EVAL_TICKET_ID=ENG-912818 \
    python3 leak_scan.py
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any


GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:6976").rstrip("/")
EVAL_TICKET = os.environ.get("EVAL_TICKET_ID", "ENG-912818")
TIMEOUT = float(os.environ.get("REQUEST_TIMEOUT", "45"))

# Fields the SME authored that MUST NOT reach an AI agent during eval.
RESTRICTED_FIELDS = [
    "root_cause",
    "resolution",
    "workaround",
    "preliminary_analysis",
    "relief_provided",
    "post_jira_closure",
]
RESTRICTED_RE = re.compile(
    r'"(?:' + "|".join(RESTRICTED_FIELDS) + r')"\s*:\s*"[^"]{4,}"',
    re.IGNORECASE,
)
TICKET_RE = re.compile(re.escape(EVAL_TICKET), re.IGNORECASE)


@dataclass
class CallResult:
    route: str
    tool: str
    ok: bool
    status_code: int
    body_preview: str
    leak_fields_matched: list[str] = field(default_factory=list)
    leak_ticket_self_ref: bool = False
    error: str = ""

    @property
    def leaked(self) -> bool:
        return bool(self.leak_fields_matched) or self.leak_ticket_self_ref


def _post(url: str, headers: dict[str, str], payload: dict[str, Any]) -> tuple[int, dict[str, str], str]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers or {}), e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, {}, f"transport-error: {e}"


def init_session(route: str) -> str:
    url = f"{GATEWAY}{route}"
    status, hdrs, body = _post(
        url,
        {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "leak-scan", "version": "0.1"},
            },
        },
    )
    sid = ""
    for k, v in hdrs.items():
        if k.lower() == "mcp-session-id":
            sid = v
            break
    if not sid:
        raise RuntimeError(f"initialize failed for {route}: status={status} body={body[:300]}")
    return sid


def _sse_data_lines(sse_body: str) -> str:
    """Join all `data: ...` lines from an SSE response body into one
    blob. MCP over streamable-HTTP always sends the result in one
    message, but if a tool streams multiple events we concatenate
    them so nothing is missed by the scanner.
    """
    parts = []
    for line in sse_body.splitlines():
        if line.startswith("data: "):
            parts.append(line[len("data: "):])
    return "\n".join(parts) if parts else sse_body


def _unwrap_text_content(raw_body: str) -> str:
    """Extract the inner text payload from an MCP tools/call response
    so the scanner sees the actual tool output instead of the
    JSON-RPC / MCP wrapper keys. Returns the original body if the
    expected shape isn't present so the scanner can still look at
    the raw bytes.
    """
    payload = _sse_data_lines(raw_body)
    pieces: list[str] = [payload]
    try:
        obj = json.loads(payload)
    except Exception:
        return raw_body
    result = obj.get("result")
    if isinstance(result, dict):
        for item in result.get("content", []) or []:
            if isinstance(item, dict) and item.get("type") == "text":
                txt = item.get("text") or ""
                if txt:
                    pieces.append(txt)
        sc = result.get("structuredContent")
        if sc:
            pieces.append(json.dumps(sc))
    return "\n".join(pieces)


def call_tool(route: str, sid: str, tool: str, args: dict[str, Any]) -> CallResult:
    url = f"{GATEWAY}{route}"
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "Mcp-Session-Id": sid,
        "X-Eval-Ticket-Id": EVAL_TICKET,
        "X-Request-Id": f"leak-scan-{uuid.uuid4()}",
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": tool, "arguments": args},
    }
    status, _hdrs, body = _post(url, headers, payload)
    res = CallResult(
        route=route,
        tool=tool,
        ok=(200 <= status < 300),
        status_code=status,
        body_preview=(body[:240].replace("\n", " ") + ("..." if len(body) > 240 else "")),
    )
    if not res.ok:
        res.error = body[:300]
        return res

    scan_blob = _unwrap_text_content(body)
    for fld in RESTRICTED_FIELDS:
        # Allow either quoted JSON key ("root_cause": "...")
        # or escaped-JSON-in-text (\"root_cause\": \"...\") since
        # many MCP tools stringify their response bodies.
        pat = re.compile(
            rf'(?:\\?")({fld})(?:\\?")\s*:\s*\\?"([^"\\]{{4,}})',
            re.IGNORECASE,
        )
        if pat.search(scan_blob):
            res.leak_fields_matched.append(fld)
    if TICKET_RE.search(scan_blob):
        res.leak_ticket_self_ref = True
    return res


# Representative tool calls per PR-95 MCP. Arguments are chosen to
# exercise the paths where SME content would leak (if it exists on the
# backend) but stay generic enough to not depend on specific data.
PR95_CALLS: list[tuple[str, str, dict[str, Any]]] = [
    # atlassian / JIRA
    ("/mcp/atlassian", "atlassian__jira_get_issue",
     {"issue_key": EVAL_TICKET}),
    # supportgpt — the four PR-95 tools
    ("/mcp/supportgpt", "supportgpt__find_similar_rcas",
     {"symptoms": "AHV hypervisor unresponsive after upgrade"}),
    ("/mcp/supportgpt", "supportgpt__search_cases",
     {"symptoms": "AHV hypervisor unresponsive after upgrade"}),
    ("/mcp/supportgpt", "supportgpt__extract_tickets",
     {"text": f"See {EVAL_TICKET} for related context."}),
    ("/mcp/supportgpt", "supportgpt__query_knowledge",
     {"topic": "AHV hypervisor restart", "limit": 3}),
    # nurag
    ("/mcp/nurag", "nurag__query",
     {"query": f"{EVAL_TICKET} root cause"}),
    # glean
    ("/mcp/glean", "glean__chat",
     {"prompt": f"Summarize everything known about {EVAL_TICKET}."}),
]


def _write_json(path: str, mode: str, results: list[CallResult]) -> None:
    ok = [r for r in results if r.ok]
    leaked = [r for r in ok if r.leaked]
    payload = {
        "mode": mode,
        "gateway": GATEWAY,
        "eval_ticket": EVAL_TICKET,
        "restricted_fields": RESTRICTED_FIELDS,
        "total": len(results),
        "ok": len(ok),
        "leaked": len(leaked),
        "failed": len(results) - len(ok),
        "leak_rate": (len(leaked) / len(ok)) if ok else 0.0,
        "results": [
            {
                "route": r.route,
                "tool": r.tool,
                "ok": r.ok,
                "status_code": r.status_code,
                "leaked": r.leaked,
                "leak_fields_matched": r.leak_fields_matched,
                "leak_ticket_self_ref": r.leak_ticket_self_ref,
                "error": r.error,
            }
            for r in results
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)


def main() -> int:
    mode_label = os.environ.get("SCAN_MODE_LABEL", "unspecified")
    json_out = os.environ.get("SCAN_JSON_OUT", "")

    print(f"# Leak scan against {GATEWAY}")
    print(f"# Eval ticket: {EVAL_TICKET}")
    print(f"# Mode label: {mode_label}")
    print(f"# Restricted fields: {', '.join(RESTRICTED_FIELDS)}")
    print()

    sessions: dict[str, str] = {}
    results: list[CallResult] = []
    for route, tool, args in PR95_CALLS:
        try:
            if route not in sessions:
                sessions[route] = init_session(route)
        except Exception as e:
            results.append(CallResult(route=route, tool=tool, ok=False,
                                       status_code=0, body_preview="",
                                       error=f"init failed: {e}"))
            continue
        res = call_tool(route, sessions[route], tool, args)
        results.append(res)

    ok = [r for r in results if r.ok]
    leaked = [r for r in ok if r.leaked]
    total = len(PR95_CALLS)
    print(f"{'route':<18} {'tool':<36} {'status':>6}  leak  notes")
    print("-" * 120)
    for r in results:
        leak = ""
        if r.leak_fields_matched:
            leak = "fields=" + ",".join(r.leak_fields_matched)
        if r.leak_ticket_self_ref:
            leak = (leak + ";" if leak else "") + "self-ref"
        if not r.ok:
            note = r.error[:60].replace("\n", " ")
        else:
            note = r.body_preview[:60]
        marker = "LEAK" if r.leaked else ("    " if r.ok else "FAIL")
        print(f"{r.route:<18} {r.tool:<36} {r.status_code:>6}  {marker:<4}  {leak or note}")

    print()
    print(f"total={total}  ok={len(ok)}  leaked={len(leaked)}  failed={total - len(ok)}")
    if ok:
        print(f"leak_rate={len(leaked) / len(ok):.1%}  (leaked / ok)")

    if json_out:
        _write_json(json_out, mode_label, results)
        print(f"wrote={json_out}")

    return 0 if leaked == [] else 1


if __name__ == "__main__":
    sys.exit(main())
