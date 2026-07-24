"""Splunk O11y AI Agent Monitoring via the OpenTelemetry GenAI utility (Phase 1b).

Emits GenAI-semconv telemetry — **AgentInvocation** + **LLMInvocation** spans PLUS the
`gen_ai.client.*` histogram metrics — that populate the O11y APM "AI Agent Monitoring"
operational panels (Requests / Errors / Tokens / Cost / Latency). Builds on the Phase 1
tracing (`tracing.py`): the GenAI handler emits through the SAME global TracerProvider, so
its spans nest under the `triage.cycle` span via asyncio contextvars; this module adds the
MeterProvider the histograms need.

SCOPE (decided 2026-07-24): O11y gets the **operational** half only. We send **NO message
content** (`CAPTURE_MESSAGE_CONTENT=NO_CONTENT`) — our prompts carry Splunk log data — and
we do NOT enable O11y evaluations. Quality/risk (toxicity/bias/…) is Galileo's job, wired
separately later. So we never populate input_messages/output_messages here; only metadata
(model, token counts, finish reason, phase) — which is all the operational panels need.
See kl-governance/docs/apm-genai-agent-monitoring-phase1b-design.md.

Fail-safe + gated, same discipline as tracing.py / usage_relay.py: with KL_GENAI_ENABLED
off or the util absent, `agent_scope()` is a no-op and `llm_call()` FALLS BACK to the
Phase 1 manual `tracing.span("llm.<phase>")` — so turning GenAI off leaves Phase 1 behavior
byte-identical, and there is never a duplicate LLM span.
"""
from __future__ import annotations

import contextlib
import logging
import os
from typing import Any, Iterator

import tracing

_ENABLED = os.environ.get("KL_GENAI_ENABLED", "false").strip().lower() == "true"
_handler: Any = None
_meter_provider: Any = None
_log = logging.getLogger(__name__)


def _provider_labels(provider: str) -> str:
    """gen_ai provider/system value. vLLM speaks the OpenAI dialect."""
    return "openai" if provider == "openai" else "anthropic"


def init_genai() -> bool:
    """Build the MeterProvider (histograms → node:4317) and the GenAI handler. Returns
    True if live. Requires the Phase 1 TracerProvider to be up (KL_TRACING_ENABLED) so the
    GenAI spans have somewhere to go. NEVER raises."""
    global _handler, _meter_provider
    if not _ENABLED:
        return False
    if not tracing.enabled():
        _log.warning("KL_GENAI_ENABLED set but tracing is off; GenAI needs the tracer "
                     "provider — enable KL_TRACING_ENABLED. GenAI disabled.")
        return False
    try:
        from opentelemetry import metrics
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.util.genai.handler import get_telemetry_handler
    except Exception as exc:  # noqa: BLE001 — missing util/SDK must not break the agent
        _log.warning("KL_GENAI_ENABLED but GenAI util/SDK unavailable (%s); disabled", exc)
        return False
    try:
        # A MeterProvider so the GenAI histograms (gen_ai.client.token.usage /
        # .operation.duration) export. Endpoint/temporality come from OTEL_* env
        # (OTEL_EXPORTER_OTLP_ENDPOINT + OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE).
        reader = PeriodicExportingMetricReader(OTLPMetricExporter())
        _meter_provider = MeterProvider(metric_readers=[reader], resource=Resource.create())
        metrics.set_meter_provider(_meter_provider)
        # The handler reads OTEL_INSTRUMENTATION_GENAI_EMITTERS (=span_metric) itself and
        # emits via the global tracer + meter providers.
        _handler = get_telemetry_handler()
    except Exception as exc:  # noqa: BLE001
        _log.warning("GenAI init failed (%s); disabled", exc)
        _handler = _meter_provider = None
        return False
    return True


def enabled() -> bool:
    return _handler is not None


# --------------------------------------------------------------------------- agent scope
@contextlib.contextmanager
def agent_scope(name: str) -> Iterator[Any]:
    """Wrap a cycle's LLM work as one GenAI AgentInvocation (→ the agent shows in AI Agent
    Monitoring). No-op when disabled. Nests under the current OTel span (triage.cycle) and
    becomes the parent of the llm_call() invocations below via contextvars."""
    if _handler is None:
        yield None
        return
    try:
        from opentelemetry.util.genai.types import AgentInvocation
        agent = AgentInvocation(name=name)
    except Exception as exc:  # noqa: BLE001
        _log.warning("agent_scope build failed (%s); skipped", exc)
        yield None
        return
    _handler.start_agent(agent)
    try:
        yield agent
    except Exception as exc:  # noqa: BLE001 — record, don't swallow
        _fail(_handler.fail_agent, agent, exc)
        raise
    else:
        _safe(_handler.stop_agent, agent)


# ----------------------------------------------------------------------------- llm call
class _LLMHandle:
    """Returned by llm_call(); .set_usage(result) records token/finish metadata after the
    call. Works for BOTH the GenAI-handler path (sets LLMInvocation fields) and the Phase 1
    fallback path (annotates the tracing span) — one call site in llm_client.py."""

    __slots__ = ("_inv", "_span")

    def __init__(self, inv: Any = None, span: Any = None):
        self._inv = inv
        self._span = span

    def set_usage(self, result: dict[str, Any]) -> None:
        usage = result.get("usage", {}) or {}
        in_t = usage.get("input_tokens")
        out_t = usage.get("output_tokens")
        cread = usage.get("cache_read_input_tokens", 0)
        cwrite = usage.get("cache_creation_input_tokens", 0)
        stop = result.get("stop_reason")
        if self._inv is not None:
            # GenAI LLMInvocation — drives the histograms + AI Agent Monitoring.
            try:
                self._inv.input_tokens = in_t
                self._inv.output_tokens = out_t
                if stop:
                    self._inv.response_finish_reasons = [stop]
                self._inv.attributes["kl.cache_read"] = cread
                self._inv.attributes["kl.cache_create"] = cwrite
            except Exception:  # noqa: BLE001
                pass
        elif self._span is not None:
            # Phase 1 fallback — annotate the manual CLIENT span (byte-identical to P1).
            tracing.annotate(self._span, **{
                "gen_ai.usage.input_tokens": in_t,
                "gen_ai.usage.output_tokens": out_t,
                "kl.cache_read": cread, "kl.cache_create": cwrite,
                "gen_ai.response.finish_reasons": [stop] if stop else None,
            })


@contextlib.contextmanager
def llm_call(model: str, provider: str, phase: str) -> Iterator[_LLMHandle]:
    """Instrument one LLM call. If GenAI is on, emits a GenAI LLMInvocation (span +
    histograms, NO content). Else falls back to the Phase 1 manual `llm.<phase>` CLIENT
    span (so KL_TRACING_ENABLED-only keeps working). Yields a handle whose .set_usage()
    the caller invokes with the call result. NO input/output messages are attached —
    operational metrics only, no prompt/response content to O11y."""
    system = _provider_labels(provider)
    if _handler is not None:
        try:
            from opentelemetry.util.genai.types import LLMInvocation
            inv = LLMInvocation(request_model=model, operation="chat", provider=system)
            inv.attributes["kl.phase"] = phase
        except Exception as exc:  # noqa: BLE001
            _log.warning("llm_call build failed (%s); falling back to span", exc)
            inv = None
        if inv is not None:
            _handler.start_llm(inv)
            try:
                yield _LLMHandle(inv=inv)
            except Exception as exc:  # noqa: BLE001
                _fail(_handler.fail_llm, inv, exc)
                raise
            else:
                _safe(_handler.stop_llm, inv)
            return
    # Fallback: Phase 1 manual span (same name/attrs as before Phase 1b).
    with tracing.span(
        "llm." + phase, kind="CLIENT",
        **{"gen_ai.operation.name": "chat", "gen_ai.system": system,
           "gen_ai.request.model": model, "peer.service": "vllm" if system == "openai" else "anthropic",
           "kl.phase": phase},
    ) as sp:
        yield _LLMHandle(span=sp)


# --------------------------------------------------------------------------------- utils
def _safe(fn: Any, *args: Any) -> None:
    try:
        fn(*args)
    except Exception as exc:  # noqa: BLE001 — a telemetry slip must not break the cycle
        _log.warning("genai stop failed: %s", exc)


def _fail(fn: Any, obj: Any, exc: BaseException) -> None:
    try:
        from opentelemetry.util.genai.types import Error
        fn(obj, Error(message=str(exc), type=type(exc).__name__))
    except Exception:  # noqa: BLE001
        _safe(fn, obj)  # best-effort


def shutdown() -> None:
    if _meter_provider is None:
        return
    try:
        _meter_provider.force_flush(timeout_millis=5000)
        _meter_provider.shutdown()
    except Exception:  # noqa: BLE001
        pass
