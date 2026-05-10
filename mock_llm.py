"""MockLLMClient — scripted LLM responses for fully-offline mock runs.

When --mock is on AND no ANTHROPIC_API_KEY is set, main.py uses this
instead of LLMClient, so the demo runs without an API call. The script
mirrors the 6 scenarios in mock_splunk: healthy / WAN-down / dedup /
escalation / recovery / healthy.
"""
from __future__ import annotations

from llm_client import DetectionDecision, TriageReports

import events


_SCRIPT: dict[int, dict] = {
    0: {
        "detection": DetectionDecision(
            summary="fleet healthy",
            correlate_stores=[],
            recovery_stores=[],
            raw={},
        ),
    },
    1: {
        "detection": DetectionDecision(
            summary="store 237 MPLS tunnel down (LTE up); LOCALIZED.",
            correlate_stores=[{"store": "237", "site": "portland",
                               "reason": "MPLS down, BFD failed, vqoe=1.8"}],
            recovery_stores=[],
            raw={},
        ),
        "triage": TriageReports(reports=[{
            "store": "237", "site": "portland",
            "action": "alert", "dedup_decision": "send",
            "dedup_rationale": "first alert for store",
            "scope": "LOCALIZED", "severity": "P2 HIGH", "confidence": "MEDIUM",
            "root_cause_domain": "WAN Transport", "root_cause_key": "SDWAN",
            "domains_affected": ["SDWAN"],
            "cascade_detected": True,
            "cascade_note": "Meraki/ISE downstream of WAN; resolving MPLS restores them.",
            "domain_summaries": {
                "SDWAN": "mpls=down vqoe=1.8 | lte=up vqoe=8.0 | site=degraded bfd_down=1",
            },
            "business_impact": {},
            "recommendation": [
                "Check MPLS circuit to store 237. Verify with carrier.",
                "Store is on LTE backup — quality will degrade under load.",
                "Escalate if LTE also fails (store goes fully offline).",
            ],
            "reasoning": "Single tunnel down with backup up; LOCALIZED P2 HIGH per SOUL.",
        }], raw={}),
    },
    2: {
        "detection": DetectionDecision(
            summary="store 237 still anomalous, no change since last poll",
            correlate_stores=[{"store": "237", "site": "portland",
                               "reason": "tunnel still down"}],
            recovery_stores=[],
            raw={},
        ),
        "triage": TriageReports(reports=[{
            "store": "237", "site": "portland",
            "action": "alert", "dedup_decision": "skip",
            "dedup_rationale": "scope/root_cause/severity unchanged from last alert",
            "scope": "LOCALIZED", "severity": "P2 HIGH", "confidence": "MEDIUM",
            "root_cause_domain": "WAN Transport", "root_cause_key": "SDWAN",
            "domains_affected": ["SDWAN"],
            "cascade_detected": True, "cascade_note": None,
            "domain_summaries": {}, "business_impact": {},
            "recommendation": [],
            "reasoning": "no change",
        }], raw={}),
    },
    3: {
        "detection": DetectionDecision(
            summary="store 237 escalating — TE now degraded too",
            correlate_stores=[{"store": "237", "site": "portland",
                               "reason": "TE response time exceeds 500ms"}],
            recovery_stores=[],
            raw={},
        ),
        "triage": TriageReports(reports=[{
            "store": "237", "site": "portland",
            "action": "alert", "dedup_decision": "send",
            "dedup_rationale": "severity escalated P2->P1; TE is a new affected domain",
            "scope": "LOCALIZED", "severity": "P1 CRITICAL", "confidence": "HIGH",
            "root_cause_domain": "WAN Transport", "root_cause_key": "SDWAN",
            "domains_affected": ["SDWAN", "TE"],
            "cascade_detected": True,
            "cascade_note": "TE alert confirms WAN root; symptoms cascade.",
            "domain_summaries": {
                "SDWAN": "mpls=down lte=up | site=degraded",
                "TE": "alert_cleared=false sev=MAJOR resp=720ms isp=degraded",
            },
            "business_impact": {},
            "recommendation": [
                "Check MPLS circuit AND ISP path (TE problem_node=comcast-pdx-core-3).",
                "Both layers degraded; escalate to network ops immediately.",
            ],
            "reasoning": "TE avg_resp_ms=720 > 500ms threshold => P1 CRITICAL.",
        }], raw={}),
    },
    4: {
        "detection": DetectionDecision(
            summary="store 237 recovered across all domains",
            correlate_stores=[],
            recovery_stores=[{
                "store": "237", "site": "portland",
                "recovered_domains": ["SDWAN", "TE"],
                "post_incident_action": "Verify POS transaction backlog cleared.",
            }],
            raw={},
        ),
    },
    5: {
        "detection": DetectionDecision(
            summary="fleet healthy",
            correlate_stores=[],
            recovery_stores=[],
            raw={},
        ),
    },
}


class MockLLMClient:
    """Implements LLMClient's surface, scripted by cycle index.

    The cycle counter advances at the same rate as MockSplunkClient
    (main.py advances both each poll), so detection + triage replies
    align with the canned Splunk data.
    """

    def __init__(self) -> None:
        self.cycle = 0

    async def detection_pass(self, scan_data, previous_alerts):
        decision = _SCRIPT[self.cycle % len(_SCRIPT)]["detection"]
        events.emit(
            "llm.detection_pass",
            mode="mock",
            summary=decision.summary,
            correlate_count=len(decision.correlate_stores),
            recovery_count=len(decision.recovery_stores),
        )
        return decision

    async def triage_pass(self, scan_data, drill_data, previous_alerts):
        reports = _SCRIPT[self.cycle % len(_SCRIPT)].get(
            "triage",
            TriageReports(reports=[], raw={}),
        )
        events.emit(
            "llm.triage_pass",
            mode="mock",
            report_count=len(reports.reports),
            stores=[r.get("store") for r in reports.reports],
        )
        return reports
