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

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from anthropic import AsyncAnthropic

import events


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
    def __init__(self, api_key: str, model: str, soul_path: str):
        self._client = AsyncAnthropic(api_key=api_key)
        self._model = model
        self._soul = Path(soul_path).read_text(encoding="utf-8")

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
    ) -> TriageReports:
        user_msg = _triage_prompt(scan_data, drill_data, previous_alerts)
        result = await self._call(
            user_text=user_msg,
            tool=TRIAGE_TOOL,
        )
        events.emit(
            "llm.triage_pass",
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
        response = await self._client.messages.create(
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
    for store, drills in drill_data.items():
        parts.append(f"\n## drill_results for store {store}\n")
        for kind, rows in drills.items():
            parts.append(
                f"\n### {kind}\n```json\n{json.dumps(rows, indent=2, default=str)}\n```\n"
            )
    return "".join(parts)
