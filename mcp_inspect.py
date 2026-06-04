"""Agent-side DefenseClaw inspection for outbound MCP tool calls (task #56).

The agent reaches bob through its sidecar MCP proxy, which DefenseClaw already
governs. But the history read (task #56) goes DIRECT to triage-mcp:8081 — it does
NOT pass through that proxy — so without this hook the agent's own DefenseClaw
would never see the `get_alert_history` call. (triage-mcp's sidecar still inspects
the resulting SPL on its end; this adds a second, independent gate at the agent
boundary and keeps the "every agent egress is inspected" invariant — tier #2 of
the #56 design.)

Mirrors triage_mcp.py's `_inspect`: before the tool call we POST the call to the
agent sidecar's inspect API; action=block aborts it. The gateway token comes from
the sidecar's mirrored identity.json (task #29) on the shared sidecar-identity
volume (mounted read-only on the agent since task #55) — loaded LAZILY because the
sidecar may write it a few seconds after this container starts. Fail-OPEN by
default so a sidecar hiccup never breaks the (enrichment-only) history read; set
DEFENSECLAW_INSPECT_FAIL_MODE=closed for fail-safe.
"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

import events

INSPECT_ENABLED = os.environ.get("DEFENSECLAW_INSPECT_ENABLED", "true").lower() == "true"
INSPECT_URL = os.environ.get(
    "DEFENSECLAW_INSPECT_URL", "http://127.0.0.1:18970/api/v1/inspect/tool"
)
INSPECT_TOKEN_PATH = os.environ.get(
    "DEFENSECLAW_TOKEN_PATH", "/var/run/sidecar-identity/identity.json"
)
INSPECT_TIMEOUT_S = float(os.environ.get("DEFENSECLAW_INSPECT_TIMEOUT", "2.0"))
INSPECT_FAIL_MODE = os.environ.get("DEFENSECLAW_INSPECT_FAIL_MODE", "open").lower()

_inspect_token: str | None = None  # lazily loaded; sidecar writes identity.json post-start


def _load_inspect_token() -> str:
    try:
        with open(INSPECT_TOKEN_PATH) as f:
            tok = json.load(f).get("token", "")
        if tok:
            return tok
    except Exception:
        pass
    return os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", "")


async def inspect_tool(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    """POST an outbound tool call to the agent sidecar's DefenseClaw inspect API.

    Returns the verdict dict, e.g. {"action": "allow"|"block"|..., ...}. Never
    raises — on any error it honors INSPECT_FAIL_MODE (open → allow, closed →
    block). Disabled / no-token → allow.
    """
    global _inspect_token
    if not INSPECT_ENABLED:
        return {"action": "allow", "mode": "disabled"}
    if not _inspect_token:
        _inspect_token = _load_inspect_token()
    if not _inspect_token:
        return {"action": "allow", "mode": "disabled", "reason": "no_token"}
    try:
        async with httpx.AsyncClient(timeout=INSPECT_TIMEOUT_S) as client:
            r = await client.post(
                INSPECT_URL,
                headers={
                    "Authorization": f"Bearer {_inspect_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-DefenseClaw-Client": "kl-triage-agent",
                },
                json={"tool": tool, "args": arguments},
            )
            r.raise_for_status()
            return r.json()
    except Exception as e:
        events.emit("agent.inspect_error", error_type=type(e).__name__,
                    error_message=str(e)[:200], fail_mode=INSPECT_FAIL_MODE)
        if INSPECT_FAIL_MODE == "closed":
            return {"action": "block", "mode": "fail_closed",
                    "reason": f"inspect failed: {type(e).__name__}"}
        return {"action": "allow", "mode": "fail_open"}


def is_blocked(verdict: dict[str, Any]) -> bool:
    return verdict.get("action") == "block"
