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


def full_outage_scan() -> dict:
    """A TRUE P1: store 237 with BOTH transports down and the site unreachable —
    not degraded-on-backup. Built from the healthy fleet with 237 overridden, since
    mock_splunk only scripts the single-tunnel (LTE-still-up) case."""
    sd = m._healthy_sdwan()
    sd[0] = {**sd[0], "tunnel_states": ["down", "down"], "transports": ["mpls", "lte"],
             "site_health": "unreachable", "reachability": "unreachable",
             "device_status": "Unreachable", "bfd_down": 4, "bfd_up": 0,
             "max_loss": 100, "min_vqoe": 0.0, "avg_jitter": 0.0, "avg_latency": 0.0}
    return {"sdwan": sd, "te": m._healthy_te(), "meraki": m._healthy_meraki(), "ise": m._healthy_ise()}


def full_outage_drill(store: str = "237") -> dict:
    return {store: {
        "drill_sdwan": [
            {"color": "mpls", "tunnel_state": "down", "jitter_ms": 0, "latency_ms": 0,
             "loss_pct": 100, "vqoe": 0.0, "first_seen": 1746000000, "last_seen": 1746000060, "event_count": 8},
            {"color": "lte", "tunnel_state": "down", "jitter_ms": 0, "latency_ms": 0,
             "loss_pct": 100, "vqoe": 0.0, "first_seen": 1746000000, "last_seen": 1746000060, "event_count": 8},
            {"color": "SITE_SUMMARY", "site_health": "unreachable", "bfd_up": 0, "bfd_down": 4,
             "reachability": "unreachable"},
        ],
        "drill_te": [], "drill_meraki": [], "drill_ise": [],
        "correlate_timeline": [
            {"_time": 1746000000, "domain": "SDWAN", "sourcetype": "cisco:sdwan:tunnelhealth",
             "detail": "mpls tunnel down"},
            {"_time": 1746000010, "domain": "SDWAN", "sourcetype": "cisco:sdwan:tunnelhealth",
             "detail": "lte tunnel down — site unreachable, both transports lost"},
        ],
    }}


# An open, UNCHANGED P2 for store 237 (matches the degraded-on-backup scan below and the
# state.snapshot() shape). Feeding this as previous_alerts should make the dedup verdict
# SKIP — nothing changed since the last card.
PREV_237_OPEN_P2 = {"237": {
    "store": "237", "site": "portland", "scope": "LOCALIZED",
    "severity": "P2 HIGH", "root_cause_key": "SDWAN",
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

    {"id": "02_wan_degraded_on_backup", "fault_type": "wan_transport_failure",
     "description": ("Store 237 MPLS tunnel down but LTE backup UP, site degraded-but-"
                     "reachable (2.5% loss) — expect P2 HIGH / SDWAN. NOT a full outage: "
                     "the store is still online on backup."),
     "previous_alerts": {}, "scan_data": scan(1), "drill_data": drill(1),
     "reference": {"detect_stores": ["237"], "severity": "P2 HIGH", "root_cause_key": "SDWAN"}},

    {"id": "03_wan_backup_te_cascade", "fault_type": "wan_transport_failure",
     "description": ("Store 237 MPLS down (LTE up) + TE degraded downstream — expect "
                     "P2 HIGH / SDWAN / cascade. Still on backup, so degraded not critical."),
     "previous_alerts": {}, "scan_data": scan(3), "drill_data": drill(3),
     "reference": {"detect_stores": ["237"], "severity": "P2 HIGH",
                   "root_cause_key": "SDWAN", "cascade": True}},

    {"id": "04_wan_dedup", "fault_type": "wan_transport_failure",
     "description": "Store 237 degraded-on-backup, UNCHANGED from an open P2 — dedup should SKIP.",
     "previous_alerts": PREV_237_OPEN_P2, "scan_data": scan(1), "drill_data": drill(1),
     "reference": {"detect_stores": ["237"], "severity": "P2 HIGH",
                   "root_cause_key": "SDWAN", "dedup_decision": "skip"}},

    {"id": "05_wan_full_outage", "fault_type": "wan_transport_failure",
     "description": ("Store 237 TRUE OUTAGE: BOTH transports down, site unreachable, 100% "
                     "loss — expect P1 CRITICAL / SDWAN. The discriminator vs 02: does the "
                     "model reserve P1 for a real outage, or over-escalate degraded-on-backup?"),
     "previous_alerts": {}, "scan_data": full_outage_scan(), "drill_data": full_outage_drill(),
     "reference": {"detect_stores": ["237"], "severity": "P1 CRITICAL", "root_cause_key": "SDWAN"}},
]

for f in FIXTURES:
    (OUT / f"{f['id']}.json").write_text(json.dumps(f, indent=2))
    print("wrote", f["id"])
print(f"\n{len(FIXTURES)} fixtures in {OUT}")
