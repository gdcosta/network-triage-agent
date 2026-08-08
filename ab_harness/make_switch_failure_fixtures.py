"""Build the Meraki-switch-failure shrink A/B pair — extends the golden-set gate
to a third fault class (after ap_offline device_offline and wifi_flap). Two
fixtures IDENTICAL except the meraki block, isolating ONE variable: does
SCAN_MERAKI_COMPACT preserve a switch-failure cascade well enough for the local
model to flag it?

  10_switch_failure_full     — meraki = full SCAN_MERAKI: store 237 shows the full
                               switch-down cascade among routine noise; others healthy.
  11_switch_failure_compact  — meraki = SCAN_MERAKI_COMPACT: routine types collapse
                               to routine_nominal; every failure signal (switch/AP
                               device_offline, port_status, wpa_deauth, rf_change,
                               vpn_registry_change) is PRESERVED. Everything else identical.

Data captured LIVE 2026-08-08 from bob index=main via the REAL SCAN_MERAKI /
SCAN_MERAKI_COMPACT queries scoped to networkId N_KL0000237 (store 237), with a
"Meraki switch failure" fault active: switch KL-237-PDX-MS-1 offline (no heartbeat),
102 port_status "Multiple ports changed state", cascading to 2 APs offline
("PoE power lost") + wpa_deauth "AP power lost". Compaction collapses 604 routine
events (wpa_auth/poe_budget_change/8021x/content_filtering/dhcp_lease/firewall_allow)
into one routine_nominal row per store; all 6 signal rows on 237 survive verbatim
(12 -> 7 rows). The COMPACT block is COMPUTED from FULL with the exact queries.py
blocklist, so the pair differs by nothing but that transform.

Run from the agent root:  python3 ab_harness/make_switch_failure_fixtures.py
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent / "fixtures"
OUT.mkdir(exist_ok=True)

# Blocklist — MUST match queries.py _MERAKI_ROUTINE_TYPES exactly.
ROUTINE_TYPES = {
    "8021x_eap_success", "wpa_auth", "dhcp_lease",
    "firewall_allow", "content_filtering", "poe_budget_change",
}

STORES = ["047", "112", "237", "305", "418", "521"]
NID = {s: f"N_KL{int(s):07d}" for s in STORES}  # 237 -> N_KL0000237


def healthy(nid):
    """The standard 9-row healthy Meraki signature for one store (full scan)."""
    return [
        {"networkId": nid, "sourcetype": "meraki:accesspoints", "type": "8021x_eap_success", "count": "20", "device_count": "1", "descriptions": "802.1X EAP authentication succeeded"},
        {"networkId": nid, "sourcetype": "meraki:accesspoints", "type": "rf_change", "count": "10", "device_count": "1", "descriptions": "RF environment changed"},
        {"networkId": nid, "sourcetype": "meraki:accesspoints", "type": "wpa_auth", "count": "50", "device_count": "3", "descriptions": "WPA authentication successful"},
        {"networkId": nid, "sourcetype": "meraki:securityappliances", "type": "content_filtering", "count": "10", "device_count": "1", "descriptions": "Content filtering event"},
        {"networkId": nid, "sourcetype": "meraki:securityappliances", "type": "dhcp_lease", "count": "10", "device_count": "1", "descriptions": "DHCP lease granted"},
        {"networkId": nid, "sourcetype": "meraki:securityappliances", "type": "firewall_allow", "count": "10", "device_count": "1", "descriptions": "Firewall rule allowed traffic"},
        {"networkId": nid, "sourcetype": "meraki:securityappliances", "type": "vpn_registry_change", "count": "10", "device_count": "1", "descriptions": "VPN connectivity change"},
        {"networkId": nid, "sourcetype": "meraki:switches", "type": "poe_budget_change", "count": "20", "device_count": "2", "descriptions": "PoE budget updated"},
        {"networkId": nid, "sourcetype": "meraki:switches", "type": "port_status", "count": "20", "device_count": "2", "descriptions": "Port status changed"},
    ]


# Store 237 = the Meraki switch failure (captured verbatim, live -15m window).
SWITCH_237 = [
    {"networkId": NID["237"], "sourcetype": "meraki:accesspoints", "type": "8021x_eap_success", "count": "100", "device_count": "1", "descriptions": "802.1X EAP authentication succeeded"},
    {"networkId": NID["237"], "sourcetype": "meraki:accesspoints", "type": "device_offline", "count": "4", "device_count": "2", "descriptions": "Access point is offline — PoE power lost"},
    {"networkId": NID["237"], "sourcetype": "meraki:accesspoints", "type": "rf_change", "count": "50", "device_count": "1", "descriptions": "RF environment changed"},
    {"networkId": NID["237"], "sourcetype": "meraki:accesspoints", "type": "wpa_auth", "count": "252", "device_count": "3", "descriptions": ["WPA authentication successful", "WPA authentication — roamed from KL-237-PDX-AP-1"]},
    {"networkId": NID["237"], "sourcetype": "meraki:accesspoints", "type": "wpa_deauth", "count": "6", "device_count": "2", "descriptions": "WPA deauthentication — AP power lost"},
    {"networkId": NID["237"], "sourcetype": "meraki:securityappliances", "type": "content_filtering", "count": "50", "device_count": "1", "descriptions": "Content filtering event"},
    {"networkId": NID["237"], "sourcetype": "meraki:securityappliances", "type": "dhcp_lease", "count": "50", "device_count": "1", "descriptions": "DHCP lease granted"},
    {"networkId": NID["237"], "sourcetype": "meraki:securityappliances", "type": "firewall_allow", "count": "50", "device_count": "1", "descriptions": "Firewall rule allowed traffic"},
    {"networkId": NID["237"], "sourcetype": "meraki:securityappliances", "type": "vpn_registry_change", "count": "50", "device_count": "1", "descriptions": "VPN connectivity change"},
    {"networkId": NID["237"], "sourcetype": "meraki:switches", "type": "device_offline", "count": "2", "device_count": "1", "descriptions": "Switch is offline — no heartbeat received for 120 seconds"},
    {"networkId": NID["237"], "sourcetype": "meraki:switches", "type": "poe_budget_change", "count": "102", "device_count": "2", "descriptions": "PoE budget updated"},
    {"networkId": NID["237"], "sourcetype": "meraki:switches", "type": "port_status", "count": "102", "device_count": "2", "descriptions": ["Multiple ports changed state", "Port status changed"]},
]


def build_full():
    rows = []
    for s in STORES:
        rows.extend(SWITCH_237 if s == "237" else healthy(NID[s]))
    rows.sort(key=lambda r: (r["networkId"], r["sourcetype"], r["type"]))
    return rows


def to_compact(full_rows):
    """Faithful port of the queries.py SCAN_MERAKI_COMPACT transform: collapse
    blocklisted (routine) types per networkId into one routine_nominal summary;
    keep every non-routine (signal) row verbatim."""
    by_nid = {}
    for r in full_rows:
        by_nid.setdefault(r["networkId"], []).append(r)

    out = []
    for nid, rows in by_nid.items():
        routine = [r for r in rows if r["type"] in ROUTINE_TYPES]
        signal = [r for r in rows if r["type"] not in ROUTINE_TYPES]
        out.extend(signal)  # signal rows preserved verbatim (incl. device_count)
        if routine:
            total = sum(int(r["count"]) for r in routine)
            n_types = len({r["type"] for r in routine})
            out.append({
                "networkId": nid, "sourcetype": "meraki", "type": "routine_nominal",
                "count": str(total),
                "descriptions": f"routine nominal: {n_types} types, {total} events",
            })
    out.sort(key=lambda r: (r["networkId"], r["sourcetype"], r["type"]))
    return out


# --- shared healthy domains (captured live, all healthy) ---------------------
SDWAN = json.loads(r"""
[{"hostname":"kl-047-pdx-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"4.2","avg_latency":"20.3","max_loss":"0.2","min_vqoe":"7"},
 {"hostname":"kl-237-pdx-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"4.5","avg_latency":"15.5","max_loss":"0.3","min_vqoe":"7"},
 {"hostname":"kl-305-sea-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"4.6","avg_latency":"15.5","max_loss":"0.3","min_vqoe":"7"},
 {"hostname":"kl-418-lax-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"5.3","avg_latency":"18.2","max_loss":"0.3","min_vqoe":"8"},
 {"hostname":"kl-521-san-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"5.8","avg_latency":"18.1","max_loss":"0.3","min_vqoe":"7"}]
""")

TE = json.loads(r"""
[{"site":"LosAngeles","alert_cleared":"true","severity":"NONE","avg_resp_ms":"48.1","max_resp_ms":"60","max_loss_pct":"0.3","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"99.5","bgp_path_changes":"6"},
 {"site":"Portland","alert_cleared":"true","severity":"NONE","avg_resp_ms":"49.4","max_resp_ms":"65","max_loss_pct":"0.3","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"100.0","bgp_path_changes":"18"},
 {"site":"SanDiego","alert_cleared":"true","severity":"NONE","avg_resp_ms":"47.4","max_resp_ms":"60","max_loss_pct":"0.2","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"99.7","bgp_path_changes":"7"},
 {"site":"Seattle","alert_cleared":"true","severity":"NONE","avg_resp_ms":"50.7","max_resp_ms":"61","max_loss_pct":"0.3","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"99.7","bgp_path_changes":"12"}]
""")

ISE = json.loads(r"""
[{"ise_event":"CISE_Passed_Authentications","device_name":"KL-047-AP","count":"37","unique_users":"4","nas_ips":["10.10.47.11","10.10.47.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-112-AP","count":"40","unique_users":"4","nas_ips":["10.10.112.11","10.10.112.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-237-AP","count":"22","unique_users":"2","nas_ips":["10.10.237.11","10.10.237.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-305-AP","count":"40","unique_users":"4","nas_ips":["10.10.50.11","10.10.50.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-418-AP","count":"40","unique_users":"4","nas_ips":["10.10.62.11","10.10.62.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-521-AP","count":"40","unique_users":"4","nas_ips":["10.10.21.11","10.10.21.13"]}]
""")

MERAKI_FULL = build_full()
MERAKI_COMPACT = to_compact(MERAKI_FULL)

REFERENCE = {"detect_stores": ["237"], "severity": None}  # detection-only test

FIXTURES = [
    {"id": "10_switch_failure_full", "fault_type": "switch_failure",
     "description": ("Store 237 Meraki switch failure: switch KL-237-PDX-MS-1 offline (no "
                     "heartbeat), 102 port_status 'Multiple ports changed state', cascading to 2 "
                     "APs offline ('PoE power lost') + wpa_deauth 'AP power lost'. FULL meraki scan; "
                     "others healthy. Captured live 2026-08-08 (networkId N_KL0000237). Expect detect=237."),
     "previous_alerts": {}, "scan_data": {"sdwan": SDWAN, "te": TE, "meraki": MERAKI_FULL, "ise": ISE},
     "drill_data": {}, "reference": REFERENCE},

    {"id": "11_switch_failure_compact", "fault_type": "switch_failure",
     "description": ("IDENTICAL to 10 except meraki = SCAN_MERAKI_COMPACT: 604 routine events "
                     "collapse to routine_nominal ('6 types') while ALL failure signals survive — "
                     "switch/AP device_offline, port_status, wpa_deauth, rf_change, vpn_registry_change "
                     "(237: 12 -> 7 rows). Tests that compaction preserves a switch-failure cascade. "
                     "Expect detect=237."),
     "previous_alerts": {}, "scan_data": {"sdwan": SDWAN, "te": TE, "meraki": MERAKI_COMPACT, "ise": ISE},
     "drill_data": {}, "reference": REFERENCE},
]

for f in FIXTURES:
    (OUT / f"{f['id']}.json").write_text(json.dumps(f, indent=2), encoding="utf-8")
    print("wrote", f["id"], "(meraki rows:", len(f["scan_data"]["meraki"]),
          "| 237 rows:", len([r for r in f["scan_data"]["meraki"] if r["networkId"] == "N_KL0000237"]), ")")
print(f"\n{len(FIXTURES)} fixtures in {OUT}")
