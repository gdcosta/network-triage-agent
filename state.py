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

    def clear(self, store: str) -> _Active | None:
        return self._active.pop(store, None)

    def is_active(self, store: str) -> bool:
        return store in self._active

    def active_stores(self) -> list[str]:
        return list(self._active.keys())
