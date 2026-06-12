"""Structured event stream on stdout — JSONL, one event per line.

Designed for an OpenTelemetry collector (k8s filelog receiver / container
log shipper) to parse and forward to Splunk. stderr remains the human-
readable operational log; stdout is the machine telemetry stream.

Every event is a self-contained JSON object with:
    ts        ISO 8601 UTC timestamp
    event     dotted name (poll.start, triage.severity, ...)
    cycle_id  per-poll-cycle id, lets you group events from one cycle
    ...       payload fields specific to the event

Decision events always carry:
    decided    the chosen value
    rationale  short human-readable why
    inputs     dict of values that drove the decision
"""
from __future__ import annotations

import contextvars
import json
import logging
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

_cycle_id: contextvars.ContextVar[str] = contextvars.ContextVar("kl_cycle_id", default="")

# Task #69a — durable token-usage capture.
# stdout rides the Splunk OTel filelog path, which starves low-volume namespaces
# under node load (see memory: reference-otel-filelog-starvation), so usage
# events are dropped on most run-days. When USAGE_SPOOL_DIR is set, these events
# are ALSO written as one JSON file each into a shared spool dir; the DefenseClaw
# sidecar drains it and POSTs each to linda HEC. The agent holds NO Splunk/HEC
# credential — the sidecar (sole linda egress) does the POST, preserving the
# agent's no-creds posture (same boundary as the audit #39 / health #64 paths).
_USAGE_SPOOL_DIR = os.environ.get("USAGE_SPOOL_DIR", "").strip()
# Token-usage events only. Names match the token dashboard's base search.
_SPOOL_EVENTS = frozenset({"llm.detection_pass", "llm.triage_pass"})

# Cycle metadata duplicated at module scope so out-of-task callers (the
# /state HTTP server triage_mcp queries) can read "what cycle is currently
# in progress?" without needing access to the polling task's context.
_latest_cycle_id: str = ""
_latest_cycle_started_at: datetime | None = None


def new_cycle() -> str:
    global _latest_cycle_id, _latest_cycle_started_at
    cid = uuid.uuid4().hex[:12]
    _cycle_id.set(cid)
    _latest_cycle_id = cid
    _latest_cycle_started_at = datetime.now(timezone.utc)
    return cid


def latest_cycle() -> tuple[str, datetime | None]:
    """Return (cycle_id, started_at) for the most recently started cycle.

    Both values are empty/None until new_cycle() has been called at least once.
    """
    return _latest_cycle_id, _latest_cycle_started_at


def emit(event: str, **fields: Any) -> None:
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
    }
    cid = _cycle_id.get()
    if cid:
        record["cycle_id"] = cid
    record.update(fields)
    # Stamp a stable id on usage events so the durable HEC copy and the lossy
    # filelog copy carry the SAME id — the dashboard dedups on it (counts once
    # even on days both paths land). Added unconditionally so the field shape is
    # uniform whether or not the spool relay is enabled.
    if event in _SPOOL_EVENTS:
        record.setdefault("usage_id", uuid.uuid4().hex)
    line = json.dumps(record, default=str, separators=(",", ":"))
    sys.stdout.write(line + "\n")
    sys.stdout.flush()
    if _USAGE_SPOOL_DIR and event in _SPOOL_EVENTS:
        _spool_usage(record, line)


def _spool_usage(record: dict[str, Any], line: str) -> None:
    """Best-effort durable copy of a usage event for the sidecar→HEC relay.

    Writes one file per event atomically (tmp + rename) so the sidecar never
    reads a half-written record. Never raises — stdout already has the event;
    a spool failure must not perturb the agent.
    """
    try:
        os.makedirs(_USAGE_SPOOL_DIR, exist_ok=True)
        name = str(record.get("usage_id") or uuid.uuid4().hex)
        tmp = os.path.join(_USAGE_SPOOL_DIR, f".{name}.tmp")
        final = os.path.join(_USAGE_SPOOL_DIR, f"{name}.json")
        with open(tmp, "w") as fh:
            fh.write(line)
        os.replace(tmp, final)
    except Exception as exc:  # noqa: BLE001 — spooling is strictly best-effort
        logging.getLogger(__name__).warning("usage spool write failed: %s", exc)


def emit_decision(event: str, decided: Any, rationale: str, inputs: dict[str, Any], **extra: Any) -> None:
    emit(event, decided=decided, rationale=rationale, inputs=inputs, **extra)


# Secrets that leak into third-party log messages. httpx logs full request
# URLs at INFO — and the Teams (Power Automate) webhook URL carries a `sig=`
# HMAC that authorizes posting (a credential). Mask it, plus any bearer /
# api-key that ever lands in a logged message, at this single formatter
# chokepoint so nothing reaches the JSONL stream / linda. Same class of fix as
# the mcp-remote bearer leak (task #67); masking the value (not the whole line)
# keeps the host/path/status useful for debugging.
_REDACT_RE = re.compile(
    r"""(?ix)
    ( \bsig=                 # Azure/Power Automate SAS signature
    | bearer\s+              # bearer tokens
    | x-api-key[=:]\s*       # Anthropic-style api key header
    | api[_-]?key[=:]\s*
    )
    ([^&\s"']+)
    """
)


def _redact(text: str) -> str:
    return _REDACT_RE.sub(r"\1<REDACTED>", text)


class _JSONFormatter(logging.Formatter):
    """Render logging.LogRecord as a JSONL event on the same schema as emit().

    Captures third-party logger output (httpx, mcp, asyncio) and our own
    log.exception tracebacks into the structured stream so the OTel
    collector sees a single uniform JSON line format. Secrets that leak into
    message text (e.g. the webhook `sig=` in httpx's request URL) are masked
    via _redact before they reach stdout.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "event": "log",
            "level": record.levelname,
            "logger": record.name,
            "message": _redact(record.getMessage()),
        }
        cid = _cycle_id.get()
        if cid:
            payload["cycle_id"] = cid
        if record.exc_info:
            exc_type, exc_val, _ = record.exc_info
            payload["exception"] = {
                "type": exc_type.__name__ if exc_type else None,
                "message": _redact(str(exc_val)) if exc_val else None,
                "traceback": _redact(self.formatException(record.exc_info)),
            }
        return json.dumps(payload, default=str, separators=(",", ":"))


def init_logging(level: int = logging.INFO) -> None:
    """Route the root logger to stdout as JSONL.

    Replaces any existing handlers so basicConfig defaults (stderr text)
    don't leak through. Unhandled tracebacks the runtime prints when the
    process dies are still allowed to land on stderr — that's the only
    thing left there, by design.
    """
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JSONFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
