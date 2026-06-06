"""Async wrapper around the Splunk MCP server.

Targets a remote Splunk MCP server that exposes `splunk_run_query`
over a stdio-bridged transport (typically `npx mcp-remote https://...`).
The bridge command is configured via SPLUNK_MCP_COMMAND /
SPLUNK_MCP_ARGS in .env.

Response shape from the tool:
    {"results": [ {row}, ... ], "truncated": bool, "total_rows": int}

When `truncated` is true, an event is emitted to stdout so silent data
loss surfaces in telemetry instead of being swallowed.
"""
from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from contextlib import AsyncExitStack, contextmanager
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import events

log = logging.getLogger(__name__)

# mcp-remote prints its request headers — including `Authorization: Bearer
# <token>` — to stderr, which the container captures into k8s_ws_logs: a
# credential leak (task #67). The token only ever appears next to "Bearer ",
# so we mask that and keep the rest of the stream for debugging.
_BEARER_RE = re.compile(r"""(Bearer\s+)[^\s"']+""", re.IGNORECASE)


@contextmanager
def _stderr_sink():
    """Yield a writable file object to hand to `stdio_client(errlog=...)`.

    Pipes the mcp-remote subprocess's stderr through a reader thread that
    masks the bearer token and forwards every other line to the real stderr —
    so connection/transport diagnostics survive without leaking the credential
    into the logs (task #67). Set SPLUNK_MCP_DEBUG_STDERR=1 to bypass redaction
    and pass raw stderr through (debug only — re-exposes the token).
    """
    if os.environ.get("SPLUNK_MCP_DEBUG_STDERR", "").strip().lower() in ("1", "true", "yes"):
        yield sys.stderr
        return

    read_fd, write_fd = os.pipe()
    # The child writes to this fd; we hold it only to expose fileno() to the
    # subprocess and to close our copy on exit so the reader sees EOF.
    write_file = os.fdopen(write_fd, "w", buffering=1, encoding="utf-8", errors="replace")

    def _pump() -> None:
        with os.fdopen(read_fd, "r", encoding="utf-8", errors="replace") as reader:
            for line in reader:
                try:
                    sys.stderr.write(_BEARER_RE.sub(r"\1<REDACTED>", line))
                    sys.stderr.flush()
                except Exception:
                    break

    thread = threading.Thread(target=_pump, name="mcp-stderr-redact", daemon=True)
    thread.start()
    try:
        yield write_file
    finally:
        # Close our write end so the child's exit drives the pipe to EOF and
        # the pump thread can finish; bounded join so cleanup never hangs.
        try:
            write_file.close()
        except Exception:
            pass
        thread.join(timeout=2.0)


class SplunkClient:
    def __init__(
        self,
        command: str,
        args: list[str],
        tool_name: str,
        row_limit: int,
        env: dict[str, str] | None = None,
    ):
        # Inherit parent process env then layer SPLUNK_MCP_ENV on top, so
        # things like NODE_TLS_REJECT_UNAUTHORIZED=0 reach the bridge
        # subprocess without polluting the agent's own env.
        full_env = dict(os.environ)
        if env:
            full_env.update(env)
        self._params = StdioServerParameters(command=command, args=args, env=full_env)
        self._tool_name = tool_name
        self._row_limit = row_limit
        self._stack: AsyncExitStack | None = None
        self._session: ClientSession | None = None

    async def __aenter__(self) -> "SplunkClient":
        self._stack = AsyncExitStack()
        # Route the mcp-remote subprocess's stderr through a redacting
        # passthrough so the `Authorization: Bearer <token>` line is masked
        # but the rest of the stream still reaches the logs (task #67). The
        # sink is entered before the transport so it tears down after it.
        errlog = self._stack.enter_context(_stderr_sink())
        try:
            cm = stdio_client(self._params, errlog=errlog)
        except TypeError:
            # mcp build without the errlog param — fall back so the data plane
            # never breaks (stderr is unredacted in that case; logged).
            log.warning("stdio_client has no errlog param; mcp-remote stderr not redacted")
            cm = stdio_client(self._params)
        read, write = await self._stack.enter_async_context(cm)
        self._session = await self._stack.enter_async_context(ClientSession(read, write))
        await self._session.initialize()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    async def run_query(
        self, spl: str, earliest_time: str, latest_time: str
    ) -> list[dict[str, Any]]:
        if self._session is None:
            raise RuntimeError("SplunkClient not opened — use 'async with'")

        result = await self._session.call_tool(
            self._tool_name,
            arguments={
                "query": spl,
                "earliest_time": earliest_time,
                "latest_time": latest_time,
                "row_limit": self._row_limit,
            },
        )
        if getattr(result, "isError", False):
            raise RuntimeError(f"splunk tool error: {result}")

        rows, truncated, total = _parse_response(result)
        if truncated:
            events.emit(
                "splunk.truncated",
                rows_returned=len(rows),
                total_rows=total,
                row_limit=self._row_limit,
                spl_prefix=spl[:120],
            )
        return rows

    async def call_tool(self, arguments: dict[str, Any]) -> Any:
        """Invoke the configured tool with arbitrary arguments and return the
        tool's payload as-is (dict or list).

        Unlike run_query, this does NOT coerce to Splunk row shape. It exists
        for tools like triage-mcp's `get_alert_history`, whose payload is a
        structured dict ({"events": [...], "event_count": N}) rather than the
        {"results": [...]} envelope run_query expects. (Task #56.)
        """
        if self._session is None:
            raise RuntimeError("SplunkClient not opened — use 'async with'")
        result = await self._session.call_tool(self._tool_name, arguments=arguments)
        if getattr(result, "isError", False):
            raise RuntimeError(f"mcp tool error ({self._tool_name}): {result}")
        return _extract_payload(result)


def _extract_payload(result: Any) -> Any:
    """Return a tool result's payload verbatim (dict/list), no row coercion.

    Prefers the JSON in the text content blocks — that's the literal value the
    tool returned, and it's what mcp-remote bridges across the stdio transport.
    Falls back to structuredContent. Returns None if neither parses.
    """
    text_parts: list[str] = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            text_parts.append(text)
    if text_parts:
        blob = "\n".join(text_parts).strip()
        try:
            return json.loads(blob)
        except json.JSONDecodeError:
            log.warning("tool returned non-JSON content; trying structuredContent")

    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, (dict, list)):
        return structured
    return None


def _parse_response(result: Any) -> tuple[list[dict[str, Any]], bool, int]:
    """Pull rows + truncation metadata from an MCP CallToolResult.

    Tries `structuredContent` first (preferred — preserves types), then
    falls back to JSON in the text content blocks.
    """
    payload: Any = None

    structured = getattr(result, "structuredContent", None)
    if isinstance(structured, dict):
        payload = structured

    if payload is None:
        text_parts: list[str] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                text_parts.append(text)
        if text_parts:
            blob = "\n".join(text_parts).strip()
            try:
                payload = json.loads(blob)
            except json.JSONDecodeError:
                log.warning("splunk tool returned non-JSON content; ignoring")
                return [], False, 0

    if payload is None:
        return [], False, 0

    if isinstance(payload, list):
        rows = [r for r in payload if isinstance(r, dict)]
        return rows, False, len(rows)

    if isinstance(payload, dict):
        raw_rows = payload.get("results") or payload.get("rows") or []
        rows = [r for r in raw_rows if isinstance(r, dict)] if isinstance(raw_rows, list) else []
        truncated = bool(payload.get("truncated", False))
        total = int(payload.get("total_rows", len(rows)) or len(rows))
        return rows, truncated, total

    return [], False, 0
