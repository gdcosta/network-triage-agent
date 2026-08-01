"""Anthropic API wrapper. SOUL.md is the system prompt; the LLM does
all detection, correlation routing, triage, dedup, and recovery
decisions. The Python code only executes queries and renders cards.

Two tools enforce structured output:

  detection_decision   — called after the 4 scan queries return.
                         LLM picks which stores to drill into and
                         which previously-active stores have recovered.

  submit_triage_reports — called after drill data is provided.
                         LLM emits a fully-populated report per store
                         including its own send/skip dedup verdict.

The system prompt is sent with cache_control so the ~6K-token SOUL.md
text isn't reprocessed every 30s. Cache TTL is 5 minutes by default,
so within-cycle calls and consecutive polls are hits.
"""
from __future__ import annotations

import asyncio
import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from anthropic import AsyncAnthropic

import events
import genai


def _require_all(schema: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy a JSON schema with every object's `required` set to all of its
    declared properties.

    The Anthropic tool_use path fills optional fields generously (Claude's tool
    training), so our schemas list only the truly-mandatory fields in `required`.
    But vLLM guided decoding only *guarantees* fields named in `required` — with
    the loose list, the model emits those, narrates the rest (severity, scope,
    recommendation, cascade_note, ...) into the free-text `reasoning`, and leaves
    the structured fields null → an incomplete card. Forcing every field required
    makes guided decoding emit the full structure. Unused fields on no_alert/skip
    reports are harmless (those cards aren't posted). Objects with only
    additionalProperties (domain_summaries/business_impact) are left as-is.
    """
    def walk(node: Any) -> None:
        if not isinstance(node, dict):
            return
        props = node.get("properties")
        if isinstance(props, dict):
            node["required"] = list(props.keys())
            for v in props.values():
                walk(v)
        items = node.get("items")
        if isinstance(items, dict):
            walk(items)

    s = copy.deepcopy(schema)
    walk(s)
    return s


# ---------- tool schemas ----------

DETECTION_TOOL: dict[str, Any] = {
    "name": "detection_decision",
    "description": (
        "Submit your detection-phase decision after analyzing the four scan "
        "results. Apply both Layer 1 (KPI thresholds) and Layer 2 (fleet "
        "outlier) detection per SOUL.md. List stores that need drill-down "
        "correlation, and stores that previously had alerts but are now "
        "fully healthy (for recovery cards). If no stores need either, "
        "return empty arrays — that means the fleet is silent."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "summary": {
                "type": "string",
                "description": "One-line description of what you observed this cycle.",
            },
            "correlate_stores": {
                "type": "array",
                "description": "Stores showing anomalies that warrant drill-down correlation.",
                "items": {
                    "type": "object",
                    "properties": {
                        "store": {"type": "string", "description": "3-digit store number"},
                        "site": {"type": "string", "description": "TE site name (city)"},
                        "reason": {"type": "string"},
                    },
                    "required": ["store", "site", "reason"],
                },
            },
            "recovery_stores": {
                "type": "array",
                "description": (
                    "Stores that had open alerts in previous_alerts but now "
                    "show fully healthy across all 4 scan domains. These get "
                    "RESOLVED cards."
                ),
                "items": {
                    "type": "object",
                    "properties": {
                        "store": {"type": "string"},
                        "site": {"type": "string"},
                        "recovered_domains": {
                            "type": "array", "items": {"type": "string"},
                        },
                        "post_incident_action": {"type": "string"},
                    },
                    "required": ["store", "site", "recovered_domains"],
                },
            },
        },
        "required": ["summary", "correlate_stores", "recovery_stores"],
    },
}


TRIAGE_TOOL: dict[str, Any] = {
    "name": "submit_triage_reports",
    "description": (
        "Submit one triage report per correlated store. Apply the SOUL.md "
        "triage stages: scope, root cause domain (from correlate_timeline "
        "first event), severity, confidence, recommendation. Decide "
        "send/skip per the SOUL deduplication rules using previous_alerts. "
        "If drill data invalidates the alert (false positive), set "
        "action='no_alert' with a rationale."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "reports": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "store": {"type": "string"},
                        "site": {"type": "string"},
                        "action": {"type": "string", "enum": ["alert", "no_alert"]},
                        "dedup_decision": {
                            "type": "string", "enum": ["send", "skip"],
                            "description": "send = post a card; skip = suppress because unchanged from last alert.",
                        },
                        "dedup_rationale": {"type": "string"},
                        "scope": {"type": "string", "enum": ["LOCALIZED", "REGIONAL", "SYSTEMIC"]},
                        "severity": {
                            "type": "string",
                            "enum": ["P1 CRITICAL", "P2 HIGH", "P3 MEDIUM", "RESOLVED"],
                            "description": (
                                "P1/P2/P3 for active issues. Use RESOLVED "
                                "when the store has fully recovered but the "
                                "card carries post-incident follow-up content "
                                "(monitoring guidance, root cause review, "
                                "transaction backlog verification). RESOLVED "
                                "renders with a green banner per SOUL.md."
                            ),
                        },
                        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
                        "root_cause_domain": {
                            "type": "string",
                            "description": "Human-readable label, e.g. 'WAN Transport'.",
                        },
                        "root_cause_key": {
                            "type": "string",
                            "enum": ["SDWAN", "TE", "MERAKI", "ISE"],
                        },
                        "domains_affected": {
                            "type": "array", "items": {"type": "string"},
                        },
                        "cascade_detected": {"type": "boolean"},
                        "cascade_note": {"type": ["string", "null"]},
                        "domain_summaries": {
                            "type": "object",
                            "description": "One-line summary per domain that has data, keyed by SDWAN/TE/MERAKI/ISE.",
                            "additionalProperties": {"type": "string"},
                        },
                        "business_impact": {
                            "type": "object",
                            "description": "Impact label -> status string. Use SOUL.md mapping.",
                            "additionalProperties": {"type": "string"},
                        },
                        "recommendation": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": (
                                "Each item is one step (immediate action, "
                                "monitoring guidance, escalation trigger, "
                                "cascade note if applicable). Plain prose only "
                                "— do NOT include leading numbers like '1.' "
                                "or '1)'; numbering is added at render time."
                            ),
                        },
                        "reasoning": {
                            "type": "string",
                            "description": "Brief audit trail: why this severity, why this root cause.",
                        },
                    },
                    "required": [
                        "store", "site", "action", "dedup_decision",
                        "dedup_rationale", "reasoning",
                    ],
                },
            },
        },
        "required": ["reports"],
    },
}


# ---------- response containers ----------

@dataclass
class DetectionDecision:
    summary: str
    correlate_stores: list[dict[str, Any]]
    recovery_stores: list[dict[str, Any]]
    raw: dict[str, Any]


@dataclass
class TriageReports:
    reports: list[dict[str, Any]]
    raw: dict[str, Any]


# ---------- client ----------

class LLMClient:
    """LLM wrapper supporting three providers, chosen at construction:

      provider="anthropic" — Anthropic SDK, forced tool_use for structured output.
                             In k8s the SDK's base_url is the DefenseClaw proxy
                             (ANTHROPIC_BASE_URL), so governance is unchanged.
      provider="vllm"      — the self-hosted OpenAI-compatible box, via the sidecar
                             LLM shim (task #1) or a direct box (harness). Structured
                             output via response_format=json_schema (guided decoding);
                             COMPACT prompts + 1-store-per-call triage chunking for the
                             bounded context window. Sends no upstream key of its own
                             weight (the shim injects the real one).
      provider="openai"    — REAL hosted OpenAI (api.openai.com) routed through the
                             DC guardrail proxy's /v1/chat/completions handler. Auth =
                             Authorization: Bearer <openai key> (passed upstream) +
                             X-DC-Auth: Bearer <gateway token> + X-DC-Target-URL. This
                             is the one path that makes DefenseClaw emit its governance
                             trace hierarchy (unlike the anthropic passthrough / vllm
                             shim). Structured output via response_format=json_object
                             (our schema uses additionalProperties maps, outside
                             OpenAI's strict json_schema subset) with the schema folded
                             into the instruction; FULL prompts like the anthropic path
                             (GPT models have the window). If per-field fidelity proves
                             insufficient, switch to OpenAI tool/function-calling.

    The "vllm" and "openai" providers share the OpenAI wire dialect (_call_openai);
    they differ only in routing/auth, prompt sizing, and response_format flavor.
    """

    def __init__(
        self,
        model: str,
        soul_path: str,
        *,
        provider: str = "anthropic",
        api_key: str = "",
        base_url: str = "",
        vllm_api_key: str = "EMPTY",
        gw_token: str = "",
        target_url: str = "",
        temperature: float | None = None,
    ):
        self._provider = provider
        self._model = model
        # OpenAI wire dialect covers both the self-hosted box and hosted OpenAI.
        self._wire = "openai" if provider in ("openai", "vllm") else "anthropic"
        # COMPACT prompts + triage chunking only for the context-bounded vLLM box;
        # hosted OpenAI and Anthropic get the full-window path.
        self._compact = provider == "vllm"
        # Hosted OpenAI (real api.openai.com through the DC proxy) vs the vLLM box.
        self._hosted = provider == "openai"
        # temperature: None = leave unset (Claude default) on the anthropic path;
        # the openai/vLLM path defaults to 0. The A/B harness passes 0 to BOTH so
        # the comparison is deterministic. Production leaves this None (unchanged).
        self._temperature = temperature
        self._soul = Path(soul_path).read_text(encoding="utf-8")
        if self._wire == "openai":
            # Full endpoint (avoid httpx base_url path-join surprises with the
            # leading-slash /chat/completions). base_url includes /v1.
            self._endpoint = base_url.rstrip("/") + "/chat/completions"
            if self._hosted:
                # Hosted OpenAI via the DC proxy. Authorization carries the OpenAI
                # key (the proxy's ExtractAPIKey reads it and forwards upstream);
                # X-DC-Auth is the gateway token; X-DC-Target-URL is api.openai.com.
                headers = {"Authorization": f"Bearer {api_key}"}
                if gw_token:
                    headers["X-DC-Auth"] = f"Bearer {gw_token}"
                if target_url:
                    headers["X-DC-Target-URL"] = target_url
                self._routed = "openai-dc-proxy"
            else:
                # vLLM box. Bearer is for the direct-to-box harness path; when
                # base_url is the sidecar shim, the shim ignores it and injects the
                # real vLLM key.
                headers = {"Authorization": f"Bearer {vllm_api_key}"}
                self._routed = "vllm-shim"
            self._http = httpx.AsyncClient(
                headers=headers,
                timeout=httpx.Timeout(120.0),  # triage passes run ~5-10s
            )
            self._client = None
        else:
            self._client = AsyncAnthropic(api_key=api_key)
            self._http = None
            self._endpoint = ""
            self._routed = "anthropic-sdk"

    async def aclose(self) -> None:
        """Release the httpx client (openai path). Called when the live toggle
        rebuilds the openai client for a new box URL, and on shutdown. No-op on
        the anthropic path (the SDK manages its own transport)."""
        if self._http is not None:
            await self._http.aclose()

    async def detection_pass(
        self,
        scan_data: dict[str, list[dict]],
        previous_alerts: dict[str, Any],
        recurrence: dict[str, Any] | None = None,
    ) -> DetectionDecision:
        user_msg = _detection_prompt(
            scan_data, previous_alerts, recurrence, compact=self._compact
        )
        with genai.llm_call(
            model=self._model, provider=self._provider, phase="detection"
        ) as _llm:
            result = await self._call(
                user_text=user_msg,
                tool=DETECTION_TOOL,
            )
            _llm.set_usage(result)
        events.emit(
            "llm.detection_pass",
            model=self._model,
            input_tokens=result["usage"]["input_tokens"],
            output_tokens=result["usage"]["output_tokens"],
            cache_read=result["usage"].get("cache_read_input_tokens", 0),
            cache_create=result["usage"].get("cache_creation_input_tokens", 0),
            stop_reason=result["stop_reason"],
            summary=result["tool_input"].get("summary", ""),
            correlate_count=len(result["tool_input"].get("correlate_stores", [])),
            recovery_count=len(result["tool_input"].get("recovery_stores", [])),
        )
        return DetectionDecision(
            summary=result["tool_input"].get("summary", ""),
            correlate_stores=result["tool_input"].get("correlate_stores", []),
            recovery_stores=result["tool_input"].get("recovery_stores", []),
            raw=result["tool_input"],
        )

    async def triage_pass(
        self,
        scan_data: dict[str, list[dict]],
        drill_data: dict[str, dict[str, list[dict]]],
        previous_alerts: dict[str, Any],
        recurrence: dict[str, Any] | None = None,
    ) -> TriageReports:
        # The triage drill payload grows ~7-8K tokens PER correlated store, so on the
        # context-bounded self-hosted path (vLLM/Qwen, 32K window) a multi-store
        # correlation overflows — 2 stores measured ~29-30K vs a 28,672 input budget,
        # while 1 store fits at ~19.6K. Chunk it ONE STORE PER CALL so every prompt
        # stays single-store sized (~9K of headroom), regardless of fault fan-out.
        # Trade-off (vLLM path only): cross-store SYNTHESIS — WIDESPREAD scope /
        # shared-root-cause incident merging — is deferred to the interactive bot;
        # per-store dedup is preserved (previous_alerts passed to each call) and
        # over-alerting is acceptable (a human/bot correlates). The frontier path
        # (Anthropic/Haiku, 200K) keeps the single all-at-once call with full
        # cross-store visibility — it has the window and doesn't get confused by the
        # fan-out. Detection still correlates across all stores upstream either way.
        if self._compact and len(drill_data) > 1:
            # vLLM path ONLY (self._compact == (provider == "vllm")). Fan the
            # one-store-per-call triage out CONCURRENTLY instead of serially: a
            # single-store triage is ~90% decode-bound (~40s wall, mostly the
            # ~600-token report at ~19 tok/s single-stream), and the box sustains
            # ~271 tok/s AGGREGATE (batched) — so N serial calls waste ~93% of its
            # decode throughput and blow the poll window (measured: 3 faults ~148s
            # vs a ~36s cadence). vLLM continuous-batching decodes the concurrent
            # calls in parallel, reclaiming that throughput.
            #
            # Bounded by a semaphore so we stay inside the box's KV budget. The
            # KV-safe ceiling ≈ kv_cache_size_tokens / triage_context; measured
            # today that's 58,448 / ~20.5K ≈ 2.8, so the default is 2 (no
            # preemption). RAISE VLLM_TRIAGE_MAX_CONCURRENCY as detection-aware
            # telemetry-shrink lowers per-call context (e.g. ~6K/call → ~9-way).
            # Per-store fail-open: one store's error no longer sinks the others'
            # cards (over-alerting is cheap; a missed P1 is not — minimal-
            # suppression policy).
            #
            # Frontier (Anthropic / hosted-OpenAI) NEVER reaches here — self._compact
            # is False, so it takes the single all-at-once call below with full
            # cross-store synthesis on its large window. This branch is vLLM-only.
            items = list(drill_data.items())
            sem = asyncio.Semaphore(
                max(1, int(os.environ.get("VLLM_TRIAGE_MAX_CONCURRENCY", "2")))
            )

            async def _triage_one(
                store: str, drills: dict[str, list[dict]]
            ) -> TriageReports:
                async with sem:
                    return await self._triage_call(
                        scan_data, {store: drills}, previous_alerts, recurrence
                    )

            results = await asyncio.gather(
                *(_triage_one(store, drills) for store, drills in items),
                return_exceptions=True,
            )
            merged: list[dict[str, Any]] = []
            for (store, _drills), res in zip(items, results):
                if isinstance(res, BaseException):
                    events.emit(
                        "llm.triage_error",
                        model=self._model,
                        store=store,
                        error=repr(res),
                    )
                    continue
                merged.extend(res.reports)
            return TriageReports(reports=merged, raw={"reports": merged})
        return await self._triage_call(scan_data, drill_data, previous_alerts, recurrence)

    async def _triage_call(
        self,
        scan_data: dict[str, list[dict]],
        drill_data: dict[str, dict[str, list[dict]]],
        previous_alerts: dict[str, Any],
        recurrence: dict[str, Any] | None = None,
    ) -> TriageReports:
        user_msg = _triage_prompt(
            scan_data, drill_data, previous_alerts, recurrence,
            compact=self._compact,
        )
        with genai.llm_call(
            model=self._model, provider=self._provider, phase="triage"
        ) as _llm:
            result = await self._call(
                user_text=user_msg,
                tool=TRIAGE_TOOL,
            )
            _llm.set_usage(result)
        events.emit(
            "llm.triage_pass",
            model=self._model,
            input_tokens=result["usage"]["input_tokens"],
            output_tokens=result["usage"]["output_tokens"],
            cache_read=result["usage"].get("cache_read_input_tokens", 0),
            cache_create=result["usage"].get("cache_creation_input_tokens", 0),
            stop_reason=result["stop_reason"],
            report_count=len(result["tool_input"].get("reports", [])),
            stores=[r.get("store") for r in result["tool_input"].get("reports", [])],
        )
        return TriageReports(
            reports=result["tool_input"].get("reports", []),
            raw=result["tool_input"],
        )

    async def _call(self, user_text: str, tool: dict[str, Any]) -> dict[str, Any]:
        if self._wire == "openai":
            return await self._call_openai(user_text, tool)
        return await self._call_anthropic(user_text, tool)

    async def _call_anthropic(self, user_text: str, tool: dict[str, Any]) -> dict[str, Any]:
        kwargs: dict[str, Any] = dict(
            model=self._model,
            max_tokens=8192,
            system=[
                {
                    "type": "text",
                    "text": self._soul,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            tools=[tool],
            tool_choice={"type": "tool", "name": tool["name"]},
            messages=[{"role": "user", "content": user_text}],
        )
        if self._temperature is not None:
            kwargs["temperature"] = self._temperature
        response = await self._client.messages.create(**kwargs)
        # Locate the tool_use block (forced by tool_choice).
        tool_input: dict[str, Any] = {}
        for block in response.content:
            if getattr(block, "type", None) == "tool_use":
                tool_input = dict(block.input or {})
                break

        usage = response.usage
        return {
            "tool_input": tool_input,
            "stop_reason": response.stop_reason,
            "usage": {
                "input_tokens": usage.input_tokens,
                "output_tokens": usage.output_tokens,
                "cache_read_input_tokens": getattr(usage, "cache_read_input_tokens", 0) or 0,
                "cache_creation_input_tokens": getattr(usage, "cache_creation_input_tokens", 0) or 0,
            },
        }

    async def _call_openai(self, user_text: str, tool: dict[str, Any]) -> dict[str, Any]:
        # Shared OpenAI-wire path for BOTH the self-hosted vLLM box and hosted
        # OpenAI. No tool_use — the tool description + schema are folded into the
        # user turn so the model gets the same semantic guidance the Anthropic tool
        # definition carried, and structured output is enforced via response_format.
        #  - vLLM: response_format=json_schema (guided decoding GUARANTEES the shape)
        #    over the _require_all-tightened schema (Qwen3 otherwise narrates optional
        #    fields into `reasoning` — see _require_all docstring).
        #  - hosted OpenAI: response_format=json_object (our schema uses
        #    additionalProperties maps, outside OpenAI's strict json_schema subset),
        #    with the ORIGINAL schema in the instruction — the same guidance the
        #    Anthropic tool_use path uses, so triage behavior stays comparable.
        # SOUL.md rides as the system message (vLLM prefix-caches it; OpenAI has no
        # explicit cache_control on this path).
        schema = tool["input_schema"] if self._hosted else _require_all(tool["input_schema"])
        instruction = (
            f"{tool['description']}\n\n"
            "Return a single JSON object that conforms to this schema (the field "
            "descriptions explain each value). Output JSON only — no prose, no "
            "markdown fences:\n"
            f"{json.dumps(schema, indent=2)}"
        )
        payload: dict[str, Any] = {
            "model": self._model,
            # vLLM is context-bounded (--max-model-len): prompt+output must fit or it
            # 400s, so 4096 (tunable via LLM_MAX_TOKENS) leaves room for the ~8K
            # prompt. Hosted OpenAI has a large window, so match the anthropic path's
            # generous 8192 completion budget.
            "max_tokens": 8192 if self._hosted else int(os.environ.get("LLM_MAX_TOKENS", "4096")),
            # Deterministic triage: reproducible severity/dedup verdicts across
            # cycles and a fair A/B. (Model default is temp 0.7.)
            "temperature": self._temperature if self._temperature is not None else 0,
            "messages": [
                {"role": "system", "content": self._soul},
                {"role": "user", "content": f"{user_text}\n\n{instruction}"},
            ],
        }
        if self._hosted:
            # json_object = valid-JSON guarantee without the strict-schema subset.
            payload["response_format"] = {"type": "json_object"}
        else:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": tool["name"], "schema": schema},
            }
            # Qwen3 DENSE models (e.g. Qwen3-32B) are HYBRID thinking models — they
            # default to emitting a <think> block before the answer. Our structured
            # detection wants direct non-thinking output, so pass the chat-template
            # switch through vLLM when VLLM_DISABLE_THINKING is set. Guided decoding
            # already forces valid JSON, but running a thinking model with thinking
            # merely suppressed-by-grammar muddies the quality read. Harmless on
            # templates that don't use the kwarg (e.g. the -Instruct-2507 MoE).
            if os.environ.get("VLLM_DISABLE_THINKING", "").strip().lower() in ("1", "true", "yes"):
                payload["chat_template_kwargs"] = {"enable_thinking": False}
        resp = await self._http.post(self._endpoint, json=payload)
        if resp.status_code >= 400:
            # Surface the endpoint's actual reason (context-length, schema, DC-proxy
            # auth/guardrail block, etc.) instead of a bare status — raise_for_status
            # hides the body that explains it.
            raise RuntimeError(
                f"{self._routed} {resp.status_code} from {self._endpoint}: {resp.text[:1000]}"
            )
        data = resp.json()
        choice = data["choices"][0]
        content = choice.get("message", {}).get("content") or "{}"
        try:
            tool_input = json.loads(content)
        except json.JSONDecodeError as e:
            # Guided decoding / json_object should make this impossible; if it fires,
            # the endpoint isn't enforcing structure — surface a short snippet.
            raise RuntimeError(
                f"{self._routed} returned non-JSON content ({e}): {content[:500]!r}"
            ) from e
        usage = data.get("usage", {}) or {}
        # Hosted OpenAI reports prompt-cache hits under prompt_tokens_details; vLLM
        # doesn't surface prefix-cache hits in OpenAI usage (zeros are fine — the
        # self-hosted path has no cache billing).
        cache_read = 0
        if self._hosted:
            cache_read = (usage.get("prompt_tokens_details") or {}).get("cached_tokens", 0) or 0
        return {
            "tool_input": tool_input if isinstance(tool_input, dict) else {},
            "stop_reason": choice.get("finish_reason"),
            "usage": {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
                "cache_read_input_tokens": cache_read,
                "cache_creation_input_tokens": 0,
            },
        }


# ---------- prompt construction ----------

# Telemetry rendering is provider-aware. The frontier path (Anthropic/Haiku, 200K
# window) gets indented JSON — readable, and it has the context to spare. The
# self-hosted path (vLLM/Qwen, ~32K window) gets COMPACT JSON: the indent=2
# whitespace alone is a large fraction of the telemetry tokens, and a WAN-fault
# fan-out has overflowed 32K by a hair (seen 2026-07-08: input 28673 + 4096 out =
# 32769). Compact separators are signal-LOSSLESS — same fields, same rows, only
# whitespace goes — so the model reasons over identical data, just denser. Keyed
# off the provider the agent already resolves per cycle (task #1 live toggle), so
# Haiku's prompt is byte-for-byte unchanged.
def _dump(obj: Any, compact: bool) -> str:
    if compact:
        return json.dumps(obj, separators=(",", ":"), default=str)
    return json.dumps(obj, indent=2, default=str)


# Opt-in last-resort per-section row cap for the context-bounded path, for an
# extreme fault fan-out where compact rendering alone still overflows 32K. This is
# signal-LOSSY (it drops rows), so it defaults OFF and marks the omission loudly
# rather than truncating silently. Tune via the VLLM_TELEMETRY_MAX_ROWS knob
# (ConfigMap/env); 0 = disabled. Only the self-hosted (compact) path is affected.
def _cap_rows(rows: Any, compact: bool) -> Any:
    if not compact or not isinstance(rows, list):
        return rows
    cap = int(os.environ.get("VLLM_TELEMETRY_MAX_ROWS", "0") or "0")
    if cap and len(rows) > cap:
        dropped = len(rows) - cap
        return rows[:cap] + [
            {"_truncated": f"{dropped} more rows omitted to fit the local model's context window"}
        ]
    return rows


def _detection_prompt(
    scan_data: dict[str, list[dict]],
    previous_alerts: dict[str, Any],
    recurrence: dict[str, Any] | None = None,
    compact: bool = False,
) -> str:
    # Task #56 stage 2: compact per-store recurrence context from the agent's OWN
    # past alerts. PRIOR context only — the scans below still decide what's firing
    # NOW; this just lets the model weight a recurring/known store vs a novel one.
    recurrence_block = ""
    if recurrence:
        recurrence_block = (
            "## prior_alert_history — recurrence context (the agent's OWN past "
            "alerts per store, last N days)\n"
            "Treat as PRIOR context, NOT a trigger: a store that has alerted "
            "repeatedly with the same root cause is a recurring/known issue "
            "(raise confidence, note the pattern); a store with little/no history "
            "that suddenly alerts is novel. Only the scans below decide whether "
            "something is firing right now.\n```json\n"
            f"{_dump(recurrence, compact)}\n```\n\n"
        )
    return (
        "PHASE: detection\n\n"
        "Below are the raw results of the 4 scan SPL queries you defined "
        "(scan_sdwan, scan_te, scan_meraki, scan_ise) for the most recent "
        "5-minute window. Apply both detection layers. Decide which stores "
        "need correlation drill-downs, and which previously-active stores "
        "have recovered.\n\n"
        "Call the detection_decision tool with your decision.\n\n"
        f"## previous_alerts (open alerts as of last poll)\n```json\n"
        f"{_dump(previous_alerts, compact)}\n```\n\n"
        f"{recurrence_block}"
        f"## scan_sdwan\n```json\n{_dump(_cap_rows(scan_data.get('sdwan', []), compact), compact)}\n```\n\n"
        f"## scan_te\n```json\n{_dump(_cap_rows(scan_data.get('te', []), compact), compact)}\n```\n\n"
        f"## scan_meraki\n```json\n{_dump(_cap_rows(scan_data.get('meraki', []), compact), compact)}\n```\n\n"
        f"## scan_ise\n```json\n{_dump(_cap_rows(scan_data.get('ise', []), compact), compact)}\n```\n"
    )


def _triage_prompt(
    scan_data: dict[str, list[dict]],
    drill_data: dict[str, dict[str, list[dict]]],
    previous_alerts: dict[str, Any],
    recurrence: dict[str, Any] | None = None,
    compact: bool = False,
) -> str:
    parts = [
        "PHASE: triage\n\n"
        "The drill queries you requested have run. For each correlated "
        "store, produce a triage report by following the SOUL.md Phase 3 "
        "stages, then emit your send/skip dedup verdict per the SOUL "
        "DEDUPLICATION rules using previous_alerts.\n\n"
        "Call the submit_triage_reports tool with one entry per store.\n\n"
        f"## previous_alerts\n```json\n{_dump(previous_alerts, compact)}\n```\n",
    ]
    parts.append(
        f"\n## scan_summary (carry-forward context)\n```json\n"
        f"{_dump({k: len(v) for k, v in scan_data.items()}, compact)}\n```\n"
    )
    # Task #56 stage 3: prior-alert recurrence for the stores being triaged, so
    # the report's confidence / severity / notes can weight a recurring vs a novel
    # store. Scoped to the drilled stores (relevance + tokens). Apply the SOUL.md
    # "PRIOR ALERT HISTORY" rules.
    relevant = {s: recurrence[s] for s in drill_data if recurrence and s in recurrence}
    if relevant:
        parts.append(
            "\n## prior_alert_history — recurrence for these stores (the agent's "
            "OWN past alerts)\n"
            "Apply the SOUL.md PRIOR ALERT HISTORY rules: a recurring store with "
            "the same root cause confirms the pattern (raise confidence; note it "
            "in the card); a repeatedly-seen ISP/external cause is a known issue, "
            "not a new store fault.\n```json\n"
            f"{_dump(relevant, compact)}\n```\n"
        )
    for store, drills in drill_data.items():
        parts.append(f"\n## drill_results for store {store}\n")
        for kind, rows in drills.items():
            parts.append(
                f"\n### {kind}\n```json\n{_dump(_cap_rows(rows, compact), compact)}\n```\n"
            )
    return "".join(parts)
