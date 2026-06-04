"""Per-store alert memory.

Pure state, no policy. The LLM is given a snapshot of this on every
poll and decides itself whether something is a fresh alert, a dedup
skip, an escalation, or a recovery — per SOUL.md.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class _Active:
    store: str
    site: str
    scope: str
    severity: str
    root_cause_key: str
    domains_affected: list[str]
    first_seen: datetime
    last_sent: datetime


@dataclass
class AlertState:
    _active: dict[str, _Active] = field(default_factory=dict)
    # Task #56 stage 1: the agent's OWN past triage.report events, read back
    # from triage-mcp's get_alert_history at startup (and refreshed per cycle in
    # later stages). Read-only context — deliberately NOT merged into _active, so
    # rehydration can never resurrect an "open" alert and trigger a spurious
    # re-post/recovery. Stage 2 feeds this to the detection/triage prompts.
    startup_history: list[dict[str, Any]] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        """Serializable view passed to the LLM each cycle."""
        return {
            store: {
                "store": a.store,
                "site": a.site,
                "scope": a.scope,
                "severity": a.severity,
                "root_cause_key": a.root_cause_key,
                "domains_affected": a.domains_affected,
                "first_seen": a.first_seen.isoformat(),
                "last_sent": a.last_sent.isoformat(),
                "open_for_minutes": (datetime.now(timezone.utc) - a.first_seen).total_seconds() / 60.0,
            }
            for store, a in self._active.items()
        }

    def record_sent(self, report: dict[str, Any]) -> None:
        store = report["store"]
        now = datetime.now(timezone.utc)
        prev = self._active.get(store)
        first_seen = prev.first_seen if prev else now
        self._active[store] = _Active(
            store=store,
            site=report.get("site", ""),
            scope=report.get("scope", ""),
            severity=report.get("severity", ""),
            root_cause_key=report.get("root_cause_key", ""),
            domains_affected=list(report.get("domains_affected", [])),
            first_seen=first_seen,
            last_sent=now,
        )

    def is_unchanged(self, report: dict[str, Any]) -> bool:
        """Deterministic dedup backstop (task #66).

        True if `report` matches the store's last-sent card on the dedup key —
        (severity, scope, root_cause_key) plus the set of domains_affected. Used
        in main.py to suppress a re-send even when the LLM sets
        dedup_decision="send", so an unchanged incident can't be spammed no
        matter how the model rationalizes it. Mirrors the same-cycle recovery
        guard (guard B): trust durable state over the LLM's momentary judgment.

        Returns False when the store has no open alert (first detection) — that
        is never a duplicate.
        """
        prev = self._active.get(report.get("store", ""))
        if prev is None:
            return False
        return (
            report.get("severity") == prev.severity
            and report.get("scope") == prev.scope
            and report.get("root_cause_key") == prev.root_cause_key
            and set(report.get("domains_affected", [])) == set(prev.domains_affected)
        )

    def clear(self, store: str) -> _Active | None:
        return self._active.pop(store, None)

    def is_active(self, store: str) -> bool:
        return store in self._active

    def active_stores(self) -> list[str]:
        return list(self._active.keys())
