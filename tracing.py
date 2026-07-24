"""OpenTelemetry distributed tracing → Splunk Observability Cloud APM (Phase 1).

A thin, FAIL-SAFE tracing layer over the triage cycle. Mirrors the discipline of
events.py / the sidecar usage relay: fully GATED (KL_TRACING_ENABLED), import-guarded
(inert if the OTel SDK isn't installed), and INCAPABLE of perturbing the agent — every
entry point degrades to a no-op rather than raising into a poll cycle.

Spans are a pure side-channel: they carry the SAME data the agent already gathers for
`events.emit(...)` (model, token usage, store ids, row counts), keyed by the same
`cycle_id` so a trace and its JSONL log lines line up. Off by default; with the flag
unset or the SDK absent, `span()` is a zero-cost no-op context manager.

Export: OTLP/gRPC to the node's OTel-agent receiver (OTEL_EXPORTER_OTLP_ENDPOINT =
http://$(K8S_NODE_IP):4317), the same collector path the governance + token metrics
use → Splunk O11y APM (us1). service.name / deployment.environment / resource attrs
come from the OTEL_* env (the SDK auto-reads them). See
kl-governance/docs/apm-tracing-agent-o11y-design.md.
"""
from __future__ import annotations

import contextlib
import logging
import os
from typing import Any, Iterator

_ENABLED = os.environ.get("KL_TRACING_ENABLED", "false").strip().lower() == "true"
_tracer: Any = None
_provider: Any = None
_log = logging.getLogger(__name__)


def init_tracing() -> bool:
    """Build the tracer provider once, at startup. Returns True if tracing is live.

    Returns False (leaving span() a no-op) when disabled or the SDK is unavailable —
    NEVER raises. Endpoint/service/resource attributes are read from the standard
    OTEL_* env by the SDK, so this stays environment-agnostic.
    """
    global _tracer, _provider
    if not _ENABLED:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except Exception as exc:  # noqa: BLE001 — missing SDK must not break the agent
        _log.warning("tracing requested but OTel SDK unavailable (%s); disabled", exc)
        return False
    try:
        # Resource.create() merges OTEL_SERVICE_NAME + OTEL_RESOURCE_ATTRIBUTES; the
        # OTLP exporter reads OTEL_EXPORTER_OTLP_ENDPOINT/PROTOCOL from env.
        _provider = TracerProvider(resource=Resource.create())
        _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        trace.set_tracer_provider(_provider)
        _tracer = trace.get_tracer("kl.triage.agent")
    except Exception as exc:  # noqa: BLE001
        _log.warning("tracing init failed (%s); disabled", exc)
        _tracer = _provider = None
        return False
    return True


def enabled() -> bool:
    return _tracer is not None


@contextlib.contextmanager
def span(name: str, kind: str = "INTERNAL", **attrs: Any) -> Iterator[Any]:
    """Start a span as the current span; yields the span object, or None when tracing
    is off. Records + marks any exception on the span, then re-raises (never swallows).
    Safe to use everywhere — a no-op when disabled."""
    if _tracer is None:
        yield None
        return
    from opentelemetry.trace import SpanKind, Status, StatusCode

    span_kind = getattr(SpanKind, kind, SpanKind.INTERNAL)
    with _tracer.start_as_current_span(name, kind=span_kind) as sp:
        _apply(sp, attrs)
        try:
            yield sp
        except Exception as exc:  # noqa: BLE001 — annotate, don't swallow
            try:
                sp.record_exception(exc)
                sp.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            except Exception:  # noqa: BLE001
                pass
            raise


def annotate(sp: Any, **attrs: Any) -> None:
    """Set attributes on a span returned by span() — no-op if sp is None (tracing off)
    or on any error. Lets call sites add attributes (e.g. GenAI token usage known only
    after the call returns) WITHOUT importing opentelemetry themselves."""
    if sp is None:
        return
    _apply(sp, attrs)


def _apply(sp: Any, attrs: dict[str, Any]) -> None:
    for key, val in attrs.items():
        if val is None:
            continue
        try:
            sp.set_attribute(key, val)
        except Exception:  # noqa: BLE001 — a bad attribute must not break the cycle
            pass


def shutdown() -> None:
    """Flush + tear down the provider on agent stop. Best-effort."""
    if _provider is None:
        return
    try:
        _provider.force_flush(timeout_millis=5000)
        _provider.shutdown()
    except Exception:  # noqa: BLE001
        pass
