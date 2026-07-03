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

import copy
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
from anthropic import AsyncAnthropic

import events


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
    """LLM wrapper supporting two providers, chosen at construction:

      provider="anthropic" — Anthropic SDK, forced tool_use for structured output.
                             In k8s the SDK's base_url is the DefenseClaw proxy
                             (ANTHROPIC_BASE_URL), so governance is unchanged.
      provider="openai"    — any OpenAI-compatible /v1 endpoint (self-hosted vLLM
                             for the #73 A/B). Same schemas, enforced via
                             response_format=json_schema (guided decoding) instead
                             of tool_use, so no server-side tool-calling flag is
                             needed. There is no Anthropic key on this path.
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
        temperature: float | None = None,
    ):
        self._provider = provider
        self._model = model
        # temperature: None = leave unset (Claude default) on the anthropic path;
        # the openai/vLLM path defaults to 0. The A/B harness passes 0 to BOTH so
        # the comparison is deterministic. Production leaves this None (unchanged).
        self._temperature = temperature
        self._soul = Path(soul_path).read_text(encoding="utf-8")
        if provider == "openai":
            # Full endpoint (avoid httpx base_url path-join surprises with the
            # leading-slash /chat/completions). base_url includes /v1.
            self._endpoint = base_url.rstrip("/") + "/chat/completions"
            self._http = httpx.AsyncClient(
                headers={"Authorization": f"Bearer {vllm_api_key}"},
                timeout=httpx.Timeout(120.0),  # vLLM triage passes run ~5-10s
            )
            self._client = None
        else:
            self._client = AsyncAnthropic(api_key=api_key)
            self._http = None
            self._endpoint = ""

    async def detection_pass(
        self,
        scan_data: dict[str, list[dict]],
        previous_alerts: dict[str, Any],
        recurrence: dict[str, Any] | None = None,
    ) -> DetectionDecision:
        user_msg = _detection_prompt(scan_data, previous_alerts, recurrence)
        result = await self._call(
            user_text=user_msg,
            tool=DETECTION_TOOL,
        )
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
        user_msg = _triage_prompt(scan_data, drill_data, previous_alerts, recurrence)
        result = await self._call(
            user_text=user_msg,
            tool=TRIAGE_TOOL,
        )
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
        if self._provider == "openai":
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
        # OpenAI-compatible (vLLM) path. No tool_use — the same tool input_schema
        # is enforced via response_format=json_schema (vLLM guided decoding). The
        # tool description + schema are folded into the user turn so the model gets
        # the same semantic guidance the Anthropic tool definition carried; the
        # grammar guarantees the shape. SOUL.md rides as the system message and is
        # auto-cached by vLLM's prefix cache (no cache_control needed). _require_all
        # tightens the schema so guided decoding emits the FULL card structure
        # (Qwen3 otherwise narrates optional fields into `reasoning` — see docstring).
        schema = _require_all(tool["input_schema"])
        instruction = (
            f"{tool['description']}\n\n"
            "Return a single JSON object that conforms to this schema (the field "
            "descriptions explain each value). Output JSON only — no prose, no "
            "markdown fences:\n"
            f"{json.dumps(schema, indent=2)}"
        )
        payload = {
            "model": self._model,
            # A self-hosted model has a bounded context window (vLLM --max-model-len,
            # e.g. 16384 on the L4). prompt_tokens + max_tokens must fit inside it or
            # vLLM returns 400 "maximum context length". Triage/detection output is
            # <1K tokens, so 4096 is generous and leaves ample room for the ~8K SOUL+
            # data prompt. Tune with LLM_MAX_TOKENS if you raise --max-model-len.
            "max_tokens": int(os.environ.get("LLM_MAX_TOKENS", "4096")),
            # Deterministic triage: reproducible severity/dedup verdicts across
            # cycles and a fair A/B vs Haiku. (Model default is temp 0.7.)
            "temperature": self._temperature if self._temperature is not None else 0,
            "messages": [
                {"role": "system", "content": self._soul},
                {"role": "user", "content": f"{user_text}\n\n{instruction}"},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": tool["name"], "schema": schema},
            },
        }
        resp = await self._http.post(self._endpoint, json=payload)
        if resp.status_code >= 400:
            # Surface vLLM's actual reason (context-length, schema, etc.) instead of
            # a bare status — raise_for_status() hides the body that explains the 400.
            raise RuntimeError(
                f"vLLM {resp.status_code} from {self._endpoint}: {resp.text[:1000]}"
            )
        data = resp.json()
        choice = data["choices"][0]
        content = choice.get("message", {}).get("content") or "{}"
        try:
            tool_input = json.loads(content)
        except json.JSONDecodeError as e:
            # Guided decoding should make this impossible; if it fires, the
            # endpoint isn't enforcing the schema — surface a short snippet.
            raise RuntimeError(
                f"vLLM returned non-JSON content ({e}): {content[:500]!r}"
            ) from e
        usage = data.get("usage", {}) or {}
        return {
            "tool_input": tool_input if isinstance(tool_input, dict) else {},
            "stop_reason": choice.get("finish_reason"),
            "usage": {
                "input_tokens": usage.get("prompt_tokens", 0),
                "output_tokens": usage.get("completion_tokens", 0),
                # vLLM prefix-cache hits aren't reported in OpenAI usage; the
                # dashboard tolerates zeros (self-hosted has no cache billing).
                "cache_read_input_tokens": 0,
                "cache_creation_input_tokens": 0,
            },
        }


# ---------- prompt construction ----------

def _detection_prompt(
    scan_data: dict[str, list[dict]],
    previous_alerts: dict[str, Any],
    recurrence: dict[str, Any] | None = None,
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
            f"{json.dumps(recurrence, indent=2, default=str)}\n```\n\n"
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
        f"{json.dumps(previous_alerts, indent=2, default=str)}\n```\n\n"
        f"{recurrence_block}"
        f"## scan_sdwan\n```json\n{json.dumps(scan_data.get('sdwan', []), indent=2, default=str)}\n```\n\n"
        f"## scan_te\n```json\n{json.dumps(scan_data.get('te', []), indent=2, default=str)}\n```\n\n"
        f"## scan_meraki\n```json\n{json.dumps(scan_data.get('meraki', []), indent=2, default=str)}\n```\n\n"
        f"## scan_ise\n```json\n{json.dumps(scan_data.get('ise', []), indent=2, default=str)}\n```\n"
    )


def _triage_prompt(
    scan_data: dict[str, list[dict]],
    drill_data: dict[str, dict[str, list[dict]]],
    previous_alerts: dict[str, Any],
    recurrence: dict[str, Any] | None = None,
) -> str:
    parts = [
        "PHASE: triage\n\n"
        "The drill queries you requested have run. For each correlated "
        "store, produce a triage report by following the SOUL.md Phase 3 "
        "stages, then emit your send/skip dedup verdict per the SOUL "
        "DEDUPLICATION rules using previous_alerts.\n\n"
        "Call the submit_triage_reports tool with one entry per store.\n\n"
        f"## previous_alerts\n```json\n{json.dumps(previous_alerts, indent=2, default=str)}\n```\n",
    ]
    parts.append(
        f"\n## scan_summary (carry-forward context)\n```json\n"
        f"{json.dumps({k: len(v) for k, v in scan_data.items()}, indent=2)}\n```\n"
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
            f"{json.dumps(relevant, indent=2, default=str)}\n```\n"
        )
    for store, drills in drill_data.items():
        parts.append(f"\n## drill_results for store {store}\n")
        for kind, rows in drills.items():
            parts.append(
                f"\n### {kind}\n```json\n{json.dumps(rows, indent=2, default=str)}\n```\n"
            )
    return "".join(parts)
