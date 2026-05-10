"""Render an LLM-produced triage report into an AdaptiveCard 1.5
payload and POST it to a Teams Workflows webhook.

This module is a dumb mapper: every section's content comes verbatim
from the LLM's report dict (domain_summaries, business_impact,
recommendation, etc.). The card structure is per SOUL.md Phase 4.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

# Match a leading "1.", "1)", "12.", " 3) ", etc. at the start of a step.
# We strip these so the renderer is the single source of numbering.
_LEADING_NUMBER = re.compile(r"^\s*\d+\s*[.)]\s*")

log = logging.getLogger(__name__)

SEVERITY_STYLE = {
    "P1 CRITICAL": ("attention", "🔴"),
    "P2 HIGH":     ("warning",   "⚠️"),
    "P3 MEDIUM":   ("accent",    "🔵"),
    "RESOLVED":    ("good",      "✅"),
}


def _store_name(
    store: str, site: str | None, registry: dict[str, str] | None = None,
) -> str:
    """Compose the human-readable store_name shown at top-level in the
    card payload. Resolution order:
      1. Fleet registry (STORE_REGISTRY_PATH) — authoritative roster.
      2. LLM-supplied site — fallback when the store isn't registered.
      3. Bare store number — last resort if neither is available."""
    if registry and store in registry:
        return registry[store]
    if site:
        return f"Store {store} - {site}"
    return f"Store {store}"


def _iso_for_template(ts: Any) -> str:
    """Format a timestamp the way Teams {{DATE()}} / {{TIME()}} expects:
    ISO 8601 in UTC with Z suffix, no fractional seconds. Teams rejects
    the +00:00 offset form and the .ffffff fractional component that
    `datetime.isoformat()` produces."""
    if isinstance(ts, datetime):
        dt = ts
    elif isinstance(ts, str) and ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now(timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_card(
    report: dict[str, Any],
    splunk_base: str,
    meraki_base: str,
    store_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    severity = report.get("severity", "P3 MEDIUM")
    style, emoji = SEVERITY_STYLE.get(severity, ("default", "•"))
    iso = _iso_for_template(report.get("timestamp"))

    body: list[dict[str, Any]] = []

    body.append({
        "type": "Container",
        "style": style,
        "items": [
            {
                "type": "TextBlock", "size": "Large", "weight": "Bolder",
                "text": f"{emoji} {severity} — Store {report.get('store','?')} ({report.get('site') or 'unknown site'})",
                "wrap": True,
            },
            {
                "type": "TextBlock", "spacing": "None", "isSubtle": True,
                "text": f"{{{{DATE({iso}, SHORT)}}}} {{{{TIME({iso})}}}}",
            },
        ],
    })

    body.append({
        "type": "Container", "separator": True, "style": "default",
        "items": [{
            "type": "FactSet",
            "facts": [
                {"title": "Scope",      "value": report.get("scope", "—")},
                {"title": "Severity",   "value": severity},
                {"title": "Root Cause", "value": report.get("root_cause_domain", "—")},
                {"title": "Confidence", "value": report.get("confidence", "—")},
                {"title": "Domains",    "value": ", ".join(report.get("domains_affected", [])) or "—"},
            ],
        }],
    })

    domain_summaries = report.get("domain_summaries") or {}
    if domain_summaries:
        body.append({
            "type": "Container", "separator": True, "style": "default",
            "items": [
                {"type": "TextBlock", "weight": "Bolder", "text": "Domain Details"},
                {"type": "FactSet", "facts": [
                    {"title": k, "value": v} for k, v in domain_summaries.items() if v
                ]},
            ],
        })

    business_impact = report.get("business_impact") or {}
    if business_impact:
        body.append({
            "type": "Container", "separator": True, "style": "default",
            "items": [
                {"type": "TextBlock", "weight": "Bolder", "text": "Business Impact"},
                {"type": "FactSet", "facts": [
                    {"title": k, "value": v} for k, v in business_impact.items()
                ]},
            ],
        })

    if report.get("cascade_detected") and report.get("cascade_note"):
        body.append({
            "type": "Container", "separator": True, "style": "warning",
            "items": [
                {"type": "TextBlock", "weight": "Bolder", "text": "Cascade Detected"},
                {"type": "TextBlock", "wrap": True, "text": report["cascade_note"]},
            ],
        })

    recommendation = report.get("recommendation") or []
    if recommendation:
        # One TextBlock per step so Adaptive Cards' `spacing` property
        # gives a visible vertical gap between items. Bold-wrapped numbers
        # (`**1.**`) keep Teams' markdown ordered-list parser from re-
        # numbering or restarting at 1.
        items: list[dict[str, Any]] = [
            {"type": "TextBlock", "weight": "Bolder", "text": "Recommended Action"}
        ]
        for i, step in enumerate(recommendation, 1):
            items.append({
                "type": "TextBlock",
                "wrap": True,
                "spacing": "Medium",
                "text": f"**{i}.** {_LEADING_NUMBER.sub('', step)}",
            })
        body.append({
            "type": "Container", "separator": True, "style": "default",
            "items": items,
        })

    store = report.get("store", "")
    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "store_id": store,
        "store_name": _store_name(store, report.get("site"), store_names),
        "body": body,
        "actions": _actions(store, splunk_base, meraki_base),
    }


def build_recovery_card(
    recovery: dict[str, Any],
    splunk_base: str,
    meraki_base: str,
    store_names: dict[str, str] | None = None,
) -> dict[str, Any]:
    iso = _iso_for_template(recovery.get("timestamp"))
    store = recovery.get("store", "?")
    site = recovery.get("site") or "unknown site"
    domains = recovery.get("recovered_domains") or []
    duration_min = recovery.get("duration_minutes")
    post_action = recovery.get("post_incident_action") or (
        "Verify POS transaction backlog cleared. Confirm all 3 APs back online."
    )

    body: list[dict[str, Any]] = [
        {
            "type": "Container", "style": "good",
            "items": [
                {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                 "text": f"✅ RESOLVED — Store {store} ({site})", "wrap": True},
                {"type": "TextBlock", "spacing": "None", "isSubtle": True,
                 "text": f"{{{{DATE({iso}, SHORT)}}}} {{{{TIME({iso})}}}}"},
            ],
        },
        {
            "type": "Container", "separator": True,
            "items": [{
                "type": "FactSet",
                "facts": [
                    {"title": "Status",    "value": "All services restored"},
                    {"title": "Recovered", "value": ", ".join(domains) or "—"},
                    {"title": "Duration",
                     "value": f"{duration_min:.1f} min" if isinstance(duration_min, (int, float)) else "—"},
                ],
            }],
        },
        {
            "type": "Container", "separator": True,
            "items": [
                {"type": "TextBlock", "weight": "Bolder", "text": "Post-Incident Action"},
                {"type": "TextBlock", "wrap": True, "text": post_action},
            ],
        },
    ]
    return {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.5",
        "store_id": store,
        "store_name": _store_name(store, recovery.get("site"), store_names),
        "body": body,
        "actions": _actions(store, splunk_base, meraki_base),
    }


def _actions(store: str, splunk_base: str, meraki_base: str) -> list[dict]:
    splunk_search = quote(
        f'index=main "kl-{store}-" OR "N_KL0000{store}" OR "KL-{store}-" earliest=-30m'
    )
    return [
        {
            "type": "Action.OpenUrl",
            "title": "Open Splunk",
            "url": f"{splunk_base.rstrip('/')}/en-US/app/search/search?q=search%20{splunk_search}",
        },
        {
            "type": "Action.OpenUrl",
            "title": "Meraki Dashboard",
            "url": f"{meraki_base.rstrip('/')}/n/N_KL0000{store}/manage/usage/list",
        },
    ]


async def post_card(webhook_url: str, card: dict[str, Any]) -> None:
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(webhook_url, json=card)
        if resp.status_code >= 400:
            log.error("Teams webhook %s: %s", resp.status_code, resp.text[:500])
            resp.raise_for_status()
