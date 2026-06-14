"""Per-store alert memory.

Pure state, no policy. The LLM is given a snapshot of this on every
poll and decides itself whether something is a fresh alert, a dedup
skip, an escalation, or a recovery — per SOUL.md.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Severity hysteresis (task #66): higher rank = more severe. Used to debounce the
# LLM flapping a store's tier on a steady incident — escalate fast, de-escalate
# slow. A downgrade must persist this many consecutive cycles to be accepted.
_SEV_RANK = {"P1": 3, "P2": 2, "P3": 1}
DOWNGRADE_HOLD_CYCLES = 2


def _sev_rank(severity: str) -> int:
    s = (severity or "").strip().upper()
    for prefix, rank in _SEV_RANK.items():
        if s.startswith(prefix):
            return rank
    return -1


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
    # Task #66 severity hysteresis: store -> (candidate_lower_severity, streak).
    # Tracks how many consecutive cycles a downgrade has been proposed, so a
    # flapping tier isn't accepted until it persists. See effective_severity.
    _downgrade: dict[str, tuple[str, int]] = field(default_factory=dict)
    # Task #66 recovery cooldown: store -> UTC time it last recovered. New alerts
    # for the store are suppressed for a window after this. See in_cooldown.
    _recovered_at: dict[str, datetime] = field(default_factory=dict)
    # Task #71 recovery hysteresis: store -> consecutive cycles an OPEN alert has
    # been absent from the detection correlate set. Recovery fires only at the
    # threshold. See advance_recovery.
    _clear_streak: dict[str, int] = field(default_factory=dict)
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

    def effective_severity(self, store: str, proposed: str) -> str:
        """Severity hysteresis (task #66): escalate fast, de-escalate slow.

        Returns the severity the agent should ACT on this cycle. Escalations (or
        an unchanged tier) apply immediately. A downgrade is HELD at the current
        confirmed tier until the lower tier has been proposed for
        DOWNGRADE_HOLD_CYCLES consecutive cycles — this damps the LLM flapping a
        stable incident between e.g. P1 and P2. A store with no open alert, or an
        unrecognized tier, is returned unchanged.

        Stateful: call once per alert report per cycle (it advances the streak).
        """
        prev = self._active.get(store)
        if prev is None:
            self._downgrade.pop(store, None)
            return proposed
        pr, cr = _sev_rank(proposed), _sev_rank(prev.severity)
        if pr < 0 or cr < 0 or pr >= cr:
            # unknown tier, or escalation / unchanged — accept now, clear pending
            self._downgrade.pop(store, None)
            return proposed
        # proposed is a downgrade — require it to persist before accepting
        cand, count = self._downgrade.get(store, ("", 0))
        count = count + 1 if cand == proposed else 1
        if count >= DOWNGRADE_HOLD_CYCLES:
            self._downgrade.pop(store, None)
            return proposed
        self._downgrade[store] = (proposed, count)
        return prev.severity

    def advance_recovery(self, faulting: set[str], clear_cycles: int) -> list[dict[str, Any]]:
        """Deterministic, hysteresis-gated recovery (task #71).

        Call once per cycle with `faulting` = the set of stores still faulting
        this cycle (the detection pass's correlate set). For each OPEN alert: a
        faulting store resets its clear-streak; a non-faulting store advances it.
        Returns recovery specs for the open alerts whose clear-streak has reached
        `clear_cycles` CONSECUTIVE non-faulting cycles — genuinely recovered and
        ready to post (caller then posts the card + calls clear()).

        Recovery is driven by this durable signal, NOT the LLM's recovery_stores
        list, which flaps on borderline signals: store 112 (2026-06-13) had a
        single false "recovered" cycle that posted a premature recovery card while
        the Meraki fault was still present (drill_meraki=4), then re-alerted P2 the
        next poll. The streak absorbs single-cycle drops. Subsumes the old
        also_correlating guard (a faulting store can't accrue a streak) and the
        no_open_alert guard (only open alerts are considered).
        """
        ready: list[dict[str, Any]] = []
        for store, a in self._active.items():
            if store in faulting:
                self._clear_streak[store] = 0
                continue
            streak = self._clear_streak.get(store, 0) + 1
            self._clear_streak[store] = streak
            if streak >= clear_cycles:
                ready.append({
                    "store": a.store,
                    "site": a.site,
                    "recovered_domains": list(a.domains_affected),
                    "first_seen": a.first_seen,
                })
        return ready

    def clear_streak(self, store: str) -> int:
        """Current consecutive non-faulting cycle count for an open alert (0 if
        none) — for observability when recovery is being held by hysteresis."""
        return self._clear_streak.get(store, 0)

    def clear(self, store: str) -> _Active | None:
        self._downgrade.pop(store, None)
        self._clear_streak.pop(store, None)
        prev = self._active.pop(store, None)
        if prev is not None:
            # A real recovery just happened — start the cooldown window.
            self._recovered_at[store] = datetime.now(timezone.utc)
        return prev

    def in_cooldown(self, store: str, window_seconds: float) -> bool:
        """Task #66 recovery cooldown: True if `store` recovered within the last
        `window_seconds`.

        Used to suppress NEW alert cards right after a recovery. The detection
        pass oscillates recover<->critical while the -5m scan window still holds
        stale fault data, so without this a just-recovered store immediately
        re-alerts (recover -> P-tier -> recover flap on 047/521, 2026-06-04).
        Set the window >= the scan horizon (EARLIEST_TIME) so the stale data ages
        out before alerting resumes.
        """
        ts = self._recovered_at.get(store)
        if ts is None:
            return False
        return (datetime.now(timezone.utc) - ts).total_seconds() < window_seconds

    def is_active(self, store: str) -> bool:
        return store in self._active

    def active_stores(self) -> list[str]:
        return list(self._active.keys())
