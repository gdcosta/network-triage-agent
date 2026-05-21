"""Triage MCP server — exposes the triage agent's state + history as MCP tools.

Wired into the KL Triage Bot (OpenClaw) so practitioners can ask
"what's happening on store 047?" and the bot can call structured tools
instead of guessing at SPL queries.

Two data sources:
  - LIVE (HTTP GET on the triage-agent pod's /state endpoint)
      → real-time AlertState, sub-second freshness, encrypted in transit
        by Cilium WireGuard
  - HISTORY (Splunk via the existing splunk_run_query MCP)
      → past triage.report events for any time window

Designed to gracefully degrade:
  - Agent down/unreachable → live tools return {"error": "agent_unreachable"}
    but Splunk-backed tools (history) still work.
  - Splunk down → history tool returns error; live tools still work.

Read-only for v1. No triage_now() or other mutation tools — those would
require the agent to accept external commands, which we deliberately
defer to a separate design conversation.

Configuration (env):
  TRIAGE_AGENT_STATE_URL    default http://triage-agent-state:8080/state
  TRIAGE_AGENT_HTTP_TIMEOUT default 3.0 (seconds — for the agent HTTP call)
  TRIAGE_MCP_PORT           default 8081
  TRIAGE_MCP_HOST           default 0.0.0.0
  TRIAGE_EVENT_INDEX        default k8s_ws_logs
  TRIAGE_SPLUNK_TIMEOUT     default 10.0 (per-query hard timeout)
  TRIAGE_SPLUNK_CACHE_TTL   default 30.0 (cache TTL for history queries)
  SPLUNK_MCP_COMMAND, SPLUNK_MCP_ARGS, SPLUNK_TOOL_NAME, SPLUNK_ROW_LIMIT
    — same as the agent's existing config; reused via splunk_client.SplunkClient

Performance notes:
  - The Splunk MCP session is opened ONCE at startup and reused for the
    process lifetime — no per-query subprocess spawn / handshake.
  - History-shaped queries (get_alert_history, get_alert fallback) are
    cached in-process by query key for SPLUNK_CACHE_TTL seconds. Live
    tools (list_active_alerts, get_recent_cycle) are NOT cached.
  - Per-query hard timeout protects against hung Splunk responses.
    Returns {"error": "splunk_timeout"} so the bot can say "Splunk's slow"
    rather than hanging.

BUG FIX (v1.0.15): asyncio event-loop mismatch resolved.
  The original code called loop.run_until_complete(_startup()) to initialise
  the SplunkClient, then called mcp.run(transport="sse") which spins up
  Uvicorn via its own asyncio.run() — a completely different event loop.
  The SplunkClient's asyncio subprocess transport and ClientSession were
  bound to the OLD loop, so every session.call_tool() invocation from
  Uvicorn's loop hung indefinitely (the asyncio Futures were waiting on a
  loop that was no longer running). TRIAGE_SPLUNK_TIMEOUT was the only
  thing preventing the hang from being infinite.

  Fix: removed the manual event-loop creation entirely. _startup() and
  _shutdown() are now wired into FastMCP via a lifespan context manager,
  which runs them inside Uvicorn's own event loop. All asyncio objects are
  created on — and used from — the same loop.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
from contextlib import asynccontextmanager
from time import monotonic
from typing import Any

import httpx
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

import events
from splunk_client import SplunkClient

# Load .env for local dev (mirrors what config.py does for the agent). In
# k8s, env comes from the Secret/ConfigMap and there's no .env file at all —
# load_dotenv silently no-ops in that case, so this is safe in both worlds.
load_dotenv()


class SplunkTimeout(Exception):
    """Raised when a Splunk query exceeds SPLUNK_QUERY_TIMEOUT seconds.

    Distinct from generic exceptions so callers can report 'slow' instead
    of 'broken'.
    """
    def __init__(self, seconds: float):
        super().__init__(f"splunk query timed out after {seconds}s")
        self.seconds = seconds

log = logging.getLogger("triage_mcp")

# --- config (env-driven so deployment knobs stay in the manifest) ----------
AGENT_STATE_URL = os.environ.get(
    "TRIAGE_AGENT_STATE_URL", "http://triage-agent-state:8080/state"
)
AGENT_HTTP_TIMEOUT = float(os.environ.get("TRIAGE_AGENT_HTTP_TIMEOUT", "3.0"))

MCP_PORT = int(os.environ.get("TRIAGE_MCP_PORT", "8081"))
MCP_HOST = os.environ.get("TRIAGE_MCP_HOST", "0.0.0.0")

# triage_mcp queries the Splunk environment that stores the agent's JSONL
# events (linda's k8s_ws_logs index), NOT the production Splunk that the
# agent itself queries for network telemetry (bob). Two distinct backends:
#   bob   = production retail-store telemetry (SDWAN, Meraki, ISE)
#         → consumed by the agent and by the bot's splunk-triage MCP
#   linda = cluster observability (OTel-collected container logs incl.
#           the agent's stdout JSONL: triage.report, recovery.posted, etc.)
#         → consumed by triage_mcp
#
# In k8s these are separate Secrets / env scopes; in local dev with a
# shared .env, set TRIAGE_MCP_SPLUNK_* explicitly (the SPLUNK_MCP_* fallback
# exists so a developer with only one Splunk available can still smoke-test).
SPLUNK_MCP_COMMAND = (
    os.environ.get("TRIAGE_MCP_SPLUNK_COMMAND")
    or os.environ.get("SPLUNK_MCP_COMMAND", "")
)
SPLUNK_MCP_ARGS = shlex.split(
    os.environ.get("TRIAGE_MCP_SPLUNK_ARGS")
    or os.environ.get("SPLUNK_MCP_ARGS", "")
)
SPLUNK_TOOL_NAME = os.environ.get("TRIAGE_MCP_SPLUNK_TOOL_NAME") or os.environ.get(
    "SPLUNK_TOOL_NAME", "splunk_run_query")
SPLUNK_ROW_LIMIT = int(os.environ.get("TRIAGE_MCP_SPLUNK_ROW_LIMIT") or os.environ.get(
    "SPLUNK_ROW_LIMIT", "1000"))


def _parse_mcp_env(value: str) -> dict[str, str]:
    """Parse comma-separated KEY=VALUE pairs into a dict.

    Matches the SPLUNK_MCP_ENV parsing used by the agent's config.py so
    operators have one consistent format. Whitespace around keys/values is
    stripped. Empty input returns an empty dict.
    """
    out: dict[str, str] = {}
    if not value:
        return out
    for pair in value.split(","):
        pair = pair.strip()
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# Extra env vars forwarded to the Splunk MCP subprocess. Same shape as
# SPLUNK_MCP_ENV for the agent — comma-separated KEY=VALUE pairs.
# Most commonly: NODE_TLS_REJECT_UNAUTHORIZED=0 because Splunk's REST API
# typically uses a self-signed cert and mcp-remote (a Node process) would
# otherwise reject it.
SPLUNK_MCP_ENV = _parse_mcp_env(
    os.environ.get("TRIAGE_MCP_ENV", "") or os.environ.get("SPLUNK_MCP_ENV", "")
)

TRIAGE_EVENT_INDEX = os.environ.get("TRIAGE_EVENT_INDEX", "k8s_ws_logs")

# Per-query timeout. Splunk normally returns in <1s for our indexed queries
# but can hang under load. Cap at 10s by default so a hung query doesn't
# block the MCP server (which would in turn hang the bot's response).
SPLUNK_QUERY_TIMEOUT = float(os.environ.get("TRIAGE_SPLUNK_TIMEOUT", "10"))

# Small in-process TTL cache for Splunk results. The chat bot will often
# ask the same question multiple times in a session ("what's firing?" then
# follow-ups about specific stores) — caching by query text dedupes the
# Splunk roundtrips for ~30s without showing user-visible staleness.
# Only history-shaped queries are cached (NOT the live-state HTTP path).
SPLUNK_CACHE_TTL = float(os.environ.get("TRIAGE_SPLUNK_CACHE_TTL", "30"))
_splunk_cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
_CACHE_MAX_ENTRIES = 100

# Splunk is reached PER-CALL: a fresh SplunkClient is opened and closed inside
# each request task (see _query_splunk). A long-lived client opened in the
# lifespan task cannot be torn down / reconnected from a request task — anyio
# cancel scopes are task-bound, so closing it cross-task raised "Attempted to
# exit cancel scope in a different task" and crashed the reconnect path. Per-call
# keeps __aenter__/__aexit__ in the same task and removes the need to reconnect.
_SPLUNK_CONFIGURED = bool(SPLUNK_MCP_COMMAND and SPLUNK_MCP_ARGS)


def _new_splunk_client() -> SplunkClient:
    return SplunkClient(
        command=SPLUNK_MCP_COMMAND,
        args=SPLUNK_MCP_ARGS,
        tool_name=SPLUNK_TOOL_NAME,
        row_limit=SPLUNK_ROW_LIMIT,
        env=SPLUNK_MCP_ENV or None,
    )


# ----------------------------- lifespan ----------------------------------
#
# FIX: All async clients (httpx + SplunkClient) MUST be initialised inside
# Uvicorn's event loop, not before mcp.run() creates it. The lifespan
# context manager runs within Uvicorn's loop, guaranteeing that the asyncio
# subprocess transport and ClientSession are bound to the correct loop.
#
# Previous pattern (BROKEN):
#   loop = asyncio.new_event_loop()
#   loop.run_until_complete(_startup())   # creates clients on 'loop'
#   mcp.run(transport="sse")              # Uvicorn creates NEW loop → mismatch
#
# Fixed pattern:
#   @asynccontextmanager
#   async def _lifespan(server): ...      # runs inside Uvicorn's loop ✓
#   mcp = FastMCP(..., lifespan=_lifespan)
#   mcp.run(transport="sse")

@asynccontextmanager
async def _lifespan(server: FastMCP):
    """FastMCP lifespan hook. No long-lived async clients are created here —
    every Splunk query (_query_splunk), agent-state fetch (_get_live_state), and
    DefenseClaw inspect (_inspect) opens its OWN client within the request task
    (per-call). So nothing is bound to one task/loop and there is no shared client
    to be torn down across the per-session lifespan re-runs of FastMCP's SSE
    transport. This is just a startup log line."""
    if _SPLUNK_CONFIGURED:
        log.info("splunk per-call mode (tool=%s row_limit=%d env_overrides=%d)",
                 SPLUNK_TOOL_NAME, SPLUNK_ROW_LIMIT, len(SPLUNK_MCP_ENV))
    else:
        log.warning("SPLUNK_MCP_COMMAND/ARGS not set — history tools will fail")

    yield  # server is running


# Disable DNS-rebinding (Host-header) protection — same reason as before.
mcp = FastMCP(
    "triage",
    transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    lifespan=_lifespan,
)


# ---------------------------- helpers ------------------------------------

async def _get_live_state() -> dict[str, Any]:
    """Fetch current AlertState from the agent.

    Returns either the parsed JSON body (which has shape
    {"cycle_id": str, "updated_at": str, "snapshot": {store_id: {...}}})
    or {"error": "<reason>", ...} on any failure.
    """
    # Per-call client (same pattern as _inspect + _query_splunk): open + close in
    # THIS request task. A lifespan-created global httpx client was unsafe here —
    # FastMCP's SSE transport re-runs the lifespan per session, so one session's
    # shutdown nulled the shared client and the next request hit
    # "http_client_uninitialized". Per-call has no shared state to corrupt.
    try:
        async with httpx.AsyncClient(timeout=AGENT_HTTP_TIMEOUT) as client:
            resp = await client.get(AGENT_STATE_URL)
            resp.raise_for_status()
            return resp.json()
    except httpx.TimeoutException:
        return {"error": "agent_timeout", "url": AGENT_STATE_URL}
    except httpx.RequestError as e:
        return {"error": "agent_unreachable", "detail": str(e), "url": AGENT_STATE_URL}
    except httpx.HTTPStatusError as e:
        return {"error": f"agent_http_{e.response.status_code}"}
    except json.JSONDecodeError as e:
        return {"error": "agent_invalid_json", "detail": str(e)}


# --- DefenseClaw runtime inspection -----------------------------------------
# Mirrors the agent's mcp_proxy.py inspect hook (task #41): before each Splunk
# query we POST the SPL to the sidecar's inspect API; action=block aborts the
# query before it reaches linda. The gateway token comes from the sidecar's
# mirrored identity.json (task #29) on the shared sidecar-identity volume —
# loaded LAZILY because the sidecar may write it a few seconds after this
# (separate) container starts. Fail-open by default so a sidecar hiccup doesn't
# break history lookups; set DEFENSECLAW_INSPECT_FAIL_MODE=closed for fail-safe.
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


class DefenseClawBlocked(Exception):
    """Raised when DefenseClaw returns action=block for a query."""
    def __init__(self, verdict: dict[str, Any]):
        self.verdict = verdict
        super().__init__(verdict.get("reason") or "blocked by DefenseClaw policy")


def _load_inspect_token() -> str:
    try:
        with open(INSPECT_TOKEN_PATH) as f:
            tok = json.load(f).get("token", "")
        if tok:
            return tok
    except Exception:
        pass
    return os.environ.get("DEFENSECLAW_GATEWAY_TOKEN", "")


async def _inspect(query: str, earliest: str, latest: str) -> dict[str, Any]:
    """POST the SPL to the sidecar's DefenseClaw inspect API; return the verdict."""
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
                    "X-DefenseClaw-Client": "kl-triage-mcp",
                },
                json={
                    "tool": SPLUNK_TOOL_NAME,
                    "args": {"query": query, "earliest_time": earliest, "latest_time": latest},
                },
            )
            r.raise_for_status()
            return r.json()
    except Exception as e:
        events.emit("triage_mcp.inspect_error", error_type=type(e).__name__,
                    error_message=str(e)[:200], fail_mode=INSPECT_FAIL_MODE)
        if INSPECT_FAIL_MODE == "closed":
            return {"action": "block", "mode": "fail_closed",
                    "reason": f"inspect failed: {type(e).__name__}"}
        return {"action": "allow", "mode": "fail_open"}


async def _query_splunk(
    spl: str,
    earliest: str,
    latest: str = "now",
    cache_key: str | None = None,
) -> list[dict[str, Any]]:
    """Run an SPL query via the existing splunk_run_query MCP tool.

    Args:
      spl, earliest, latest: passed through to the Splunk MCP tool
      cache_key: if provided, results are cached in-process for
        SPLUNK_CACHE_TTL seconds. Use stable, descriptive keys (e.g.
        "history:047:24h") so the cache hits across repeated bot turns.
        Omit for queries where freshness matters.

    Raises:
      SplunkTimeout if the query exceeds SPLUNK_QUERY_TIMEOUT seconds
      RuntimeError if the Splunk client isn't initialized
      (other exceptions: passed through from the MCP transport)
    """
    if not _SPLUNK_CONFIGURED:
        raise RuntimeError("splunk_client not configured")

    # Cache check
    if cache_key is not None:
        cached = _splunk_cache.get(cache_key)
        if cached is not None and (monotonic() - cached[0]) < SPLUNK_CACHE_TTL:
            return cached[1]

    # DefenseClaw runtime inspection — abort out-of-policy queries before they
    # reach linda (e.g. an internal index injected via a crafted store_id).
    # Fail-open by default (see _inspect).
    verdict = await _inspect(spl, earliest, latest)
    if verdict.get("action") == "block":
        events.emit("triage_mcp.query_blocked", reason=verdict.get("reason"),
                    severity=verdict.get("severity"), spl_prefix=spl[:120])
        raise DefenseClawBlocked(verdict)

    # Execute with a hard timeout (a Splunk hang would otherwise hang the bot).
    # Per-call connection: open a fresh SplunkClient inside THIS request task so
    # the stdio_client's anyio context is entered AND exited in the same task —
    # no long-lived/stale connection to reconnect, and no cross-task teardown
    # (which previously crashed with "exit cancel scope in a different task").
    # Cost is spawning mcp-remote per query (~1-2s), fine for chat history.
    try:
        async with _new_splunk_client() as client:
            rows = await asyncio.wait_for(
                client.run_query(spl, earliest, latest),
                timeout=SPLUNK_QUERY_TIMEOUT,
            )
    except asyncio.TimeoutError:
        raise SplunkTimeout(SPLUNK_QUERY_TIMEOUT)

    # Cache store + opportunistic stale-entry sweep (bounded growth)
    if cache_key is not None:
        _splunk_cache[cache_key] = (monotonic(), rows)
        if len(_splunk_cache) > _CACHE_MAX_ENTRIES:
            cutoff = monotonic() - SPLUNK_CACHE_TTL
            for k in [k for k, (ts, _) in _splunk_cache.items() if ts < cutoff]:
                _splunk_cache.pop(k, None)

    return rows


# ---------------------------- tools --------------------------------------

@mcp.tool()
async def list_active_alerts() -> dict[str, Any]:
    """List every store the agent currently has an active alert on.

    Returns:
      {
        "active_alerts": [ {store, site, scope, severity, root_cause_key,
                            domains_affected, first_seen, last_sent,
                            open_for_minutes}, ... ],
        "active_count": int,
        "cycle_id": str,
        "updated_at": str (ISO-8601),
        "source": "live"
      }
    Or {"error": "<reason>", ...} if the agent is unreachable.
    """
    state = await _get_live_state()
    if "error" in state:
        return state
    snapshot = state.get("snapshot", {})
    return {
        "source": "live",
        "active_alerts": list(snapshot.values()),
        "active_count": len(snapshot),
        "cycle_id": state.get("cycle_id"),
        "updated_at": state.get("updated_at"),
    }


@mcp.tool()
async def get_alert(store_id: str) -> dict[str, Any]:
    """Get the agent's view of a specific store.

    First checks the agent's live state. If the store is currently in an
    active alert, returns its full record. If not, falls back to Splunk
    to find the most recent past triage.report event for the store.

    Returns:
      {"source": "live"|"splunk_history"|"none", "active": bool,
       "store": str, ...} on success
      {"error": "<reason>", ...} on failure
    """
    if not store_id or not isinstance(store_id, str):
        return {"error": "invalid_store_id"}

    # First try: live state from agent
    state = await _get_live_state()
    if "error" not in state:
        snapshot = state.get("snapshot", {})
        if store_id in snapshot:
            alert = dict(snapshot[store_id])
            alert["source"] = "live"
            alert["active"] = True
            alert["cycle_id"] = state.get("cycle_id")
            return alert

    # Fall back to Splunk for the most recent past report on this store
    if not _SPLUNK_CONFIGURED:
        return {"error": "no_data_sources", "store": store_id, "active": False}

    spl = (
        f'search index={TRIAGE_EVENT_INDEX} sourcetype="kube:container:triage-agent" '
        f'"triage.report" event="triage.report" store="{store_id}" earliest=-7d '
        f'| sort -_time | head 1 | table _time _raw'
    )
    try:
        rows = await _query_splunk(spl, "-7d", "now",
                                   cache_key=f"last_event:{store_id}")
        if not rows:
            return {"source": "none", "store": store_id, "active": False,
                    "message": "no active alert and no triage events in last 7d"}
        latest = rows[0]
        return {
            "source": "splunk_history",
            "store": store_id,
            "active": False,
            "last_event_at": latest.get("_time"),
            "raw": latest.get("_raw", ""),
        }
    except DefenseClawBlocked as e:
        return {"error": "blocked_by_policy", "reason": str(e),
                "severity": e.verdict.get("severity"), "store": store_id, "active": False}
    except SplunkTimeout as e:
        return {"error": "splunk_timeout", "timeout_seconds": e.seconds,
                "store": store_id, "active": False}
    except Exception as e:
        return {"error": "splunk_query_failed", "detail": str(e), "store": store_id}


@mcp.tool()
async def get_recent_cycle() -> dict[str, Any]:
    """Get information about the agent's most recent poll cycle.

    Useful for "what is the agent doing right now?" — returns the live
    cycle id, when state was last refreshed, and a count of active alerts.

    Returns:
      {"source": "live", "cycle_id": str, "updated_at": str,
       "active_count": int} on success
      {"error": "<reason>"} if the agent isn't reachable
    """
    state = await _get_live_state()
    if "error" in state:
        return state
    snapshot = state.get("snapshot", {})
    return {
        "source": "live",
        "cycle_id": state.get("cycle_id"),
        "updated_at": state.get("updated_at"),
        "active_count": len(snapshot),
        "active_stores": list(snapshot.keys()),
    }


@mcp.tool()
async def get_alert_history(store_id: str | None = None, hours: int = 24) -> dict[str, Any]:
    """Authoritative history of a store's PAST ALERTS, as recorded by the triage agent.

    USE THIS for ANY question about a store's alert history, past alerts,
    recurrence, or patterns — e.g. "has store X been flaky", "how often has X
    alerted", "third time this week?", "what's X's history", "any issues this
    week/yesterday". This is the ONLY source of the agent's alert records.

    Do NOT use raw Splunk SPL (the splunk_run_query tool) to answer
    alert-history questions: that queries raw network telemetry, which does NOT
    contain the agent's alerts and will give a wrong/re-derived answer. Raw SPL
    is only for confirming CURRENT live telemetry, after this tool.

    Args:
      store_id: optional — limit to a specific store. If omitted, returns
        events for all stores in the time window.
      hours: how far back to look (default 24, max 168).

    Returns:
      {"source": "splunk_history", "hours": int, "store": str|null,
       "event_count": int, "events": [ {ts, store, severity, scope,
       root_cause, action, dedup_decision, ...}, ... ]} on success
      {"error": "<reason>"} on failure
    """
    if not _SPLUNK_CONFIGURED:
        return {"error": "splunk_unavailable"}
    if hours <= 0 or hours > 168:
        return {"error": "invalid_hours", "detail": "hours must be 1..168"}
    earliest = f"-{hours}h"

    if store_id:
        store_clause = f'store="{store_id}" '
    else:
        store_clause = ""

    # Events are JSON; Splunk auto-extracts `event`/`store` as fields, so filter
    # with FIELD comparisons (event="triage.report" store="047"). Do NOT use quoted
    # phrase literals like "event=\"...\"" — that searches for the literal text
    # key="val" (with '='), which never matches the JSON form key:"val" (with ':')
    # and silently returns 0 rows even when the data is present. (`"triage.report"`
    # bare token kept up front purely as an index-time narrowing filter.)
    spl = (
        f'search index={TRIAGE_EVENT_INDEX} sourcetype="kube:container:triage-agent" '
        f'"triage.report" event="triage.report" {store_clause}earliest={earliest} '
        f'| sort -_time | head 100 | table _time _raw'
    )
    try:
        rows = await _query_splunk(
            spl, earliest, "now",
            cache_key=f"history:{store_id or 'all'}:{hours}h",
        )
    except DefenseClawBlocked as e:
        return {"error": "blocked_by_policy", "reason": str(e),
                "severity": e.verdict.get("severity"), "store": store_id, "hours": hours}
    except SplunkTimeout as e:
        return {"error": "splunk_timeout", "timeout_seconds": e.seconds,
                "store": store_id, "hours": hours}
    except Exception as e:
        return {"error": "splunk_query_failed", "detail": str(e)}

    parsed: list[dict[str, Any]] = []
    for r in rows:
        raw = r.get("_raw", "")
        try:
            ev = json.loads(raw)
            parsed.append({
                "ts": r.get("_time") or ev.get("ts"),
                "store": ev.get("store"),
                "severity": ev.get("severity"),
                "scope": ev.get("scope"),
                "root_cause": ev.get("root_cause"),
                "action": ev.get("action"),
                "dedup_decision": ev.get("dedup_decision"),
                "confidence": ev.get("confidence"),
                "cycle_id": ev.get("cycle_id"),
            })
        except json.JSONDecodeError:
            # Splunk row not parseable as JSON — include raw for debugging
            parsed.append({"ts": r.get("_time"), "_raw": raw[:300]})
    return {
        "source": "splunk_history",
        "hours": hours,
        "store": store_id,
        "event_count": len(parsed),
        "events": parsed,
    }


# ---------------------------- main ---------------------------------------

def main() -> None:
    # Reuse the agent's JSONL logger so this MCP server's logs end up in
    # Splunk via OTel the same way.
    events.init_logging()
    log.info("triage_mcp starting on %s:%d", MCP_HOST, MCP_PORT)
    events.emit("triage_mcp.start", host=MCP_HOST, port=MCP_PORT,
                agent_state_url=AGENT_STATE_URL)

    # mcp.run() delegates to Uvicorn which manages its own event loop.
    # _lifespan() runs startup/shutdown INSIDE that loop (httpx client), and each
    # Splunk query opens its own SplunkClient within the request task — so every
    # asyncio object is created on, and torn down from, the same task. No mismatch.
    mcp.settings.host = MCP_HOST
    mcp.settings.port = MCP_PORT
    mcp.run(transport="sse")

    events.emit("triage_mcp.stop")
    log.info("triage_mcp stopped")


if __name__ == "__main__":
    main()
