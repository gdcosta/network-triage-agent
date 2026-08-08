"""Build the Wi-Fi-flap shrink A/B pair — closes the gate gap left by the
ap_offline pair (which only covered `device_offline`). Two fixtures IDENTICAL
except the meraki block, to isolate ONE variable: does SCAN_MERAKI_COMPACT
summarizing the routine `wpa_auth` churn change whether the local model flags a
Wi-Fi *flap* whose real signal is the preserved `wpa_deauth`?

  08_wifi_flap_full     — meraki = full SCAN_MERAKI: store 305 shows wpa_auth +
                          wpa_deauth (the flap), all other stores healthy.
  09_wifi_flap_compact  — meraki = SCAN_MERAKI_COMPACT: 305's wpa_auth collapses
                          into routine_nominal; wpa_deauth is PRESERVED (it is not
                          on the blocklist). Everything else identical.

Why this pair matters: the compact scan blocklists `wpa_auth` (a routine type),
so the flap's re-association churn is summarized — but `wpa_deauth` is kept full.
This isolates whether losing the auth-volume context blunts flap detection.

Data captured LIVE 2026-08-08 from bob index=main via the REAL SCAN_MERAKI /
SCAN_MERAKI_COMPACT queries scoped to networkId N_KL0000305 (store 305), with a
"Camera Wi-Fi flap" fault active. Over the agent's -5m window store 305's
networkId shows ONLY wpa_auth(18) + wpa_deauth(36) — so the compact transform
leaves wpa_deauth fully intact. sdwan/te/ise healthy; other stores healthy.

The COMPACT block is COMPUTED from the FULL block with the exact queries.py
blocklist, so the two fixtures differ by nothing but that transform.

Run from the agent root:  python3 ab_harness/make_wifi_flap_fixtures.py
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
NID = {s: f"N_KL{int(s):07d}" for s in STORES}  # 305 -> N_KL0000305


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


# Store 305 = the Wi-Fi flap. Captured live: networkId N_KL0000305 shows ONLY
# wpa_auth (routine, re-association churn) + wpa_deauth (SIGNAL, disassociation).
FLAP_305 = [
    {"networkId": NID["305"], "sourcetype": "meraki:accesspoints", "type": "wpa_auth", "count": "18", "device_count": "1", "descriptions": "WPA authentication"},
    {"networkId": NID["305"], "sourcetype": "meraki:accesspoints", "type": "wpa_deauth", "count": "36", "device_count": "1", "descriptions": "WPA deauthentication — client RSSI below threshold"},
]


def build_full():
    rows = []
    for s in STORES:
        rows.extend(FLAP_305 if s == "305" else healthy(NID[s]))
    rows.sort(key=lambda r: (r["networkId"], r["sourcetype"], r["type"]))
    return rows


def to_compact(full_rows):
    """Apply the queries.py SCAN_MERAKI_COMPACT transform: collapse blocklisted
    (routine) types per networkId into one routine_nominal summary; keep every
    non-routine (signal) row verbatim. Faithful port of the SPL."""
    by_nid = {}
    for r in full_rows:
        by_nid.setdefault(r["networkId"], []).append(r)

    out = []
    for nid, rows in by_nid.items():
        has_deauth = any(r["type"] == "wpa_deauth" for r in rows)

        def _routine(r):
            # FLAP FIX (matches queries.py): keep wpa_auth as a SIGNAL row when this
            # networkId also has wpa_deauth (preserve the auth-vs-deauth ratio).
            if r["type"] == "wpa_auth" and has_deauth:
                return False
            return r["type"] in ROUTINE_TYPES

        routine = [r for r in rows if _routine(r)]
        signal = [r for r in rows if not _routine(r)]
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

# ISE healthy for all stores — 305's flap is intentionally isolated to Meraki so
# the ONLY cross-fixture difference is the compact transform on the meraki block.
ISE = json.loads(r"""
[{"ise_event":"CISE_Passed_Authentications","device_name":"KL-047-AP","count":"37","unique_users":"4","nas_ips":["10.10.47.11","10.10.47.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-112-AP","count":"40","unique_users":"4","nas_ips":["10.10.112.11","10.10.112.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-237-AP","count":"40","unique_users":"4","nas_ips":["10.10.237.11","10.10.237.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-305-AP","count":"38","unique_users":"4","nas_ips":["10.10.50.11","10.10.50.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-418-AP","count":"40","unique_users":"4","nas_ips":["10.10.62.11","10.10.62.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-521-AP","count":"40","unique_users":"4","nas_ips":["10.10.21.11","10.10.21.13"]}]
""")

MERAKI_FULL = build_full()
MERAKI_COMPACT = to_compact(MERAKI_FULL)

REFERENCE = {"detect_stores": ["305"], "severity": None}  # detection-only test

FIXTURES = [
    {"id": "08_wifi_flap_full", "fault_type": "wifi_flap",
     "description": ("Store 305 Wi-Fi flap (wpa_auth churn + wpa_deauth 'client RSSI below "
                     "threshold'), FULL meraki scan; all other stores healthy. Captured live "
                     "2026-08-08 (networkId N_KL0000305, agent -5m window). Expect detect=305."),
     "previous_alerts": {}, "scan_data": {"sdwan": SDWAN, "te": TE, "meraki": MERAKI_FULL, "ise": ISE},
     "drill_data": {}, "reference": REFERENCE},

    {"id": "09_wifi_flap_compact", "fault_type": "wifi_flap",
     "description": ("IDENTICAL to 08 except meraki = SCAN_MERAKI_COMPACT: 305's routine wpa_auth "
                     "collapses into routine_nominal ('1 types') while wpa_deauth is PRESERVED as a "
                     "full signal row. Tests whether summarizing the auth churn blunts flap "
                     "detection. Expect detect=305 (compact should NOT blind it)."),
     "previous_alerts": {}, "scan_data": {"sdwan": SDWAN, "te": TE, "meraki": MERAKI_COMPACT, "ise": ISE},
     "drill_data": {}, "reference": REFERENCE},
]

for f in FIXTURES:
    (OUT / f"{f['id']}.json").write_text(json.dumps(f, indent=2), encoding="utf-8")
    print("wrote", f["id"], "(meraki rows:", len(f["scan_data"]["meraki"]),
          "| 305 rows:", len([r for r in f["scan_data"]["meraki"] if r["networkId"] == "N_KL0000305"]), ")")
print(f"\n{len(FIXTURES)} fixtures in {OUT}")
