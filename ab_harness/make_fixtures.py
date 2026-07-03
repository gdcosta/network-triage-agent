"""Generate A/B fixtures (scan_data + drill_data + previous_alerts) from the
canned shapes in mock_splunk.py, so the corpus matches EXACTLY what the agent's
detection/triage passes consume in production.

Run from the agent root:  python3 ab_harness/make_fixtures.py
Writes ab_harness/fixtures/*.json (static — the harness needs no import of this
file or mock_splunk at run time).

This seeds the WAN-fault scenarios mock_splunk already scripts. To expand coverage
to the rest of the taxonomy (ap_hardware_failure, ise_policy_rejection,
camera_wifi_flap, switch_failure, wan_degraded — see kl-scenario-controller/
event-templates.json), add scan/drill shapes for those and append fixtures here,
or hand-author JSON in fixtures/ following the same schema.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import mock_splunk as m  # noqa: E402

OUT = Path(__file__).resolve().parent / "fixtures"
OUT.mkdir(exist_ok=True)


def scan(scenario: int) -> dict:
    return {
        "sdwan": m._scan_for(scenario, "scan_sdwan"),
        "te": m._scan_for(scenario, "scan_te"),
        "meraki": m._scan_for(scenario, "scan_meraki"),
        "ise": m._scan_for(scenario, "scan_ise"),
    }


def drill(scenario: int, store: str = "237") -> dict:
    # Real drill_data keys (correlation.py run_drills): drill_sdwan/te/meraki/ise
    # + correlate_timeline. mock_splunk names the timeline kind "timeline".
    return {store: {
        "drill_sdwan": m._drill_for(scenario, "drill_sdwan"),
        "drill_te": m._drill_for(scenario, "drill_te"),
        "drill_meraki": m._drill_for(scenario, "drill_meraki"),
        "drill_ise": m._drill_for(scenario, "drill_ise"),
        "correlate_timeline": m._drill_for(scenario, "timeline"),
    }}


# An open, UNCHANGED P1 for store 237 — matches state.snapshot() shape. Feeding this
# as previous_alerts should make the triage dedup verdict SKIP (nothing changed).
PREV_237_OPEN_P1 = {"237": {
    "store": "237", "site": "portland", "scope": "LOCALIZED",
    "severity": "P1 CRITICAL", "root_cause_key": "SDWAN",
    "domains_affected": ["SDWAN"],
    "first_seen": "2026-07-03T18:00:00+00:00",
    "last_sent": "2026-07-03T18:00:00+00:00",
    "open_for_minutes": 30.0,
}}

FIXTURES = [
    {"id": "01_healthy", "fault_type": "none",
     "description": "Healthy fleet — both models should stay SILENT (no detection).",
     "previous_alerts": {}, "scan_data": scan(0), "drill_data": {},
     "reference": {"detect_stores": [], "severity": None}},

    {"id": "02_wan_transport_failure", "fault_type": "wan_transport_failure",
     "description": "Store 237 MPLS tunnel down, 100% loss — expect P1 CRITICAL / SDWAN.",
     "previous_alerts": {}, "scan_data": scan(1), "drill_data": drill(1),
     "reference": {"detect_stores": ["237"], "severity": "P1 CRITICAL", "root_cause_key": "SDWAN"}},

    {"id": "03_wan_te_cascade", "fault_type": "wan_transport_failure",
     "description": "Store 237 WAN down + TE degraded downstream — expect P1 / SDWAN / cascade.",
     "previous_alerts": {}, "scan_data": scan(3), "drill_data": drill(3),
     "reference": {"detect_stores": ["237"], "severity": "P1 CRITICAL",
                   "root_cause_key": "SDWAN", "cascade": True}},

    {"id": "04_wan_dedup", "fault_type": "wan_transport_failure",
     "description": "Store 237 WAN down, UNCHANGED from an open P1 — dedup should SKIP.",
     "previous_alerts": PREV_237_OPEN_P1, "scan_data": scan(1), "drill_data": drill(1),
     "reference": {"detect_stores": ["237"], "severity": "P1 CRITICAL",
                   "root_cause_key": "SDWAN", "dedup_decision": "skip"}},
]

for f in FIXTURES:
    (OUT / f"{f['id']}.json").write_text(json.dumps(f, indent=2))
    print("wrote", f["id"])
print(f"\n{len(FIXTURES)} fixtures in {OUT}")
