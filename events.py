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
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

_cycle_id: contextvars.ContextVar[str] = contextvars.ContextVar("kl_cycle_id", default="")

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
    sys.stdout.write(json.dumps(record, default=str, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def emit_decision(event: str, decided: Any, rationale: str, inputs: dict[str, Any], **extra: Any) -> None:
    emit(event, decided=decided, rationale=rationale, inputs=inputs, **extra)


class _JSONFormatter(logging.Formatter):
    """Render logging.LogRecord as a JSONL event on the same schema as emit().

    Captures third-party logger output (httpx, mcp, asyncio) and our own
    log.exception tracebacks into the structured stream so the OTel
    collector sees a single uniform JSON line format.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "event": "log",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        cid = _cycle_id.get()
        if cid:
            payload["cycle_id"] = cid
        if record.exc_info:
            exc_type, exc_val, _ = record.exc_info
            payload["exception"] = {
                "type": exc_type.__name__ if exc_type else None,
                "message": str(exc_val) if exc_val else None,
                "traceback": self.formatException(record.exc_info),
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
