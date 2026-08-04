"""Build the AP-offline shrink A/B pair — two fixtures IDENTICAL except the
meraki block, to isolate ONE variable: does removing routine Meraki noise help
the local model surface an explicit `device_offline` it currently misses?

  06_ap_offline_full     — meraki = full SCAN_MERAKI output (device_offline buried
                           among 49 rows). Reproduces the LIVE miss on the vLLM path.
  07_ap_offline_compact  — meraki = SCAN_MERAKI_COMPACT output (device_offline is
                           1 of 4 rows on 112; routine_nominal flags 112 as "1 types"
                           vs "6" on healthy stores). The shrink under test.

Everything else (sdwan/te/ise healthy, previous_alerts, reference) is shared, so any
detection difference is PURELY the meraki noise level — no SOUL change involved.

Data captured LIVE 2026-08-02 from bob index=main over the agent's exact -5m scan
window, with the Meraki `device_offline` fault active on store 112 (N_KL0000112).
sdwan/te/ise were healthy in that window; ISE corroborates weakly (KL-112-AP shows
18 auths/2 users vs ~40/4 elsewhere — fewer clients through the dead AP).

Run from the agent root:  python3 ab_harness/make_ap_offline_fixtures.py
"""
import json
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parent / "fixtures"
OUT.mkdir(exist_ok=True)

# --- shared healthy domains (captured live, -5m window) ----------------------
SDWAN = json.loads(r"""
[{"hostname":"kl-047-pdx-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"4.2","avg_latency":"20.3","max_loss":"0.2","min_vqoe":"7"},
 {"hostname":"kl-237-pdx-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"4.5","avg_latency":"15.5","max_loss":"0.3","min_vqoe":"7"},
 {"hostname":"kl-305-sea-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"4.6","avg_latency":"15.5","max_loss":"0.3","min_vqoe":"7"},
 {"hostname":"kl-418-lax-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"5.3","avg_latency":"18.2","max_loss":"0.3","min_vqoe":"8"},
 {"hostname":"kl-521-san-rtr-1","site_health":"good","device_status":"normal","reachability":"reachable","bfd_up":"2","bfd_down":"0","tunnel_states":"up","transports":"mpls","avg_jitter":"5.8","avg_latency":"18.1","max_loss":"0.3","min_vqoe":"7"}]
""")

TE = json.loads(r"""
[{"site":"LosAngeles","alert_cleared":"true","severity":"NONE","avg_resp_ms":"48.1","max_resp_ms":"60","max_loss_pct":"0.3","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"99.5","bgp_path_changes":"6"},
 {"site":"Portland","alert_cleared":"true","severity":"NONE","avg_resp_ms":"49.36842105263158","max_resp_ms":"65","max_loss_pct":"0.3","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"100.0","bgp_path_changes":"18"},
 {"site":"SanDiego","alert_cleared":"true","severity":"NONE","avg_resp_ms":"47.4","max_resp_ms":"60","max_loss_pct":"0.2","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"99.7","bgp_path_changes":"7"},
 {"site":"Seattle","alert_cleared":"true","severity":"NONE","avg_resp_ms":"50.7","max_resp_ms":"61","max_loss_pct":"0.3","max_jitter":"8","isp_status":"healthy","edge_status":"healthy","path_conclusion":"All hops within threshold - no issues detected","bgp_status":"healthy","bgp_reach_pct":"99.7","bgp_path_changes":"12"}]
""")

ISE = json.loads(r"""
[{"ise_event":"CISE_Passed_Authentications","device_name":"KL-047-AP","count":"37","unique_users":"4","nas_ips":["10.10.47.11","10.10.47.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-112-AP","count":"18","unique_users":"2","nas_ips":["10.10.112.11","10.10.112.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-237-AP","count":"40","unique_users":"4","nas_ips":["10.10.237.11","10.10.237.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-305-AP","count":"40","unique_users":"4","nas_ips":["10.10.50.11","10.10.50.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-418-AP","count":"40","unique_users":"4","nas_ips":["10.10.62.11","10.10.62.13"]},
 {"ise_event":"CISE_Passed_Authentications","device_name":"KL-521-AP","count":"40","unique_users":"4","nas_ips":["10.10.21.11","10.10.21.13"]}]
""")

# --- meraki: the ONLY thing that differs between the two fixtures -------------
MERAKI_FULL = json.loads(r"""
[{"networkId":"N_KL0000047","sourcetype":"meraki:accesspoints","type":"8021x_eap_success","count":"20","device_count":"1","descriptions":"802.1X EAP authentication succeeded"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:accesspoints","type":"wpa_auth","count":"50","device_count":"3","descriptions":"WPA authentication successful"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:securityappliances","type":"content_filtering","count":"10","device_count":"1","descriptions":"Content filtering event"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:securityappliances","type":"dhcp_lease","count":"10","device_count":"1","descriptions":"DHCP lease granted"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:securityappliances","type":"firewall_allow","count":"10","device_count":"1","descriptions":"Firewall rule allowed traffic"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:switches","type":"poe_budget_change","count":"20","device_count":"2","descriptions":"PoE budget updated"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:accesspoints","type":"device_offline","count":"10","device_count":"1","descriptions":"Access point is offline — no heartbeat received for 120 seconds"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:accesspoints","type":"wpa_auth","count":"20","device_count":"2","descriptions":"WPA authentication — roamed from KL-112-VAN-AP-2"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:accesspoints","type":"wpa_deauth","count":"20","device_count":"1","descriptions":"WPA deauthentication — AP unreachable"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:switches","type":"port_status","count":"10","device_count":"1","descriptions":"Port status changed"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:accesspoints","type":"8021x_eap_success","count":"19","device_count":"1","descriptions":"802.1X EAP authentication succeeded"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:accesspoints","type":"rf_change","count":"9","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:accesspoints","type":"wpa_auth","count":"46","device_count":"3","descriptions":"WPA authentication successful"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:securityappliances","type":"content_filtering","count":"10","device_count":"1","descriptions":"Content filtering event"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:securityappliances","type":"dhcp_lease","count":"9","device_count":"1","descriptions":"DHCP lease granted"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:securityappliances","type":"firewall_allow","count":"10","device_count":"1","descriptions":"Firewall rule allowed traffic"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"9","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:switches","type":"poe_budget_change","count":"18","device_count":"2","descriptions":"PoE budget updated"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:switches","type":"port_status","count":"18","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:accesspoints","type":"8021x_eap_success","count":"20","device_count":"1","descriptions":"802.1X EAP authentication succeeded"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:accesspoints","type":"wpa_auth","count":"50","device_count":"3","descriptions":"WPA authentication successful"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:securityappliances","type":"content_filtering","count":"10","device_count":"1","descriptions":"Content filtering event"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:securityappliances","type":"dhcp_lease","count":"10","device_count":"1","descriptions":"DHCP lease granted"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:securityappliances","type":"firewall_allow","count":"10","device_count":"1","descriptions":"Firewall rule allowed traffic"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:switches","type":"poe_budget_change","count":"20","device_count":"2","descriptions":"PoE budget updated"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:accesspoints","type":"8021x_eap_success","count":"20","device_count":"1","descriptions":"802.1X EAP authentication succeeded"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:accesspoints","type":"wpa_auth","count":"50","device_count":"3","descriptions":"WPA authentication successful"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:securityappliances","type":"content_filtering","count":"10","device_count":"1","descriptions":"Content filtering event"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:securityappliances","type":"dhcp_lease","count":"10","device_count":"1","descriptions":"DHCP lease granted"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:securityappliances","type":"firewall_allow","count":"10","device_count":"1","descriptions":"Firewall rule allowed traffic"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:switches","type":"poe_budget_change","count":"20","device_count":"2","descriptions":"PoE budget updated"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:accesspoints","type":"8021x_eap_success","count":"20","device_count":"1","descriptions":"802.1X EAP authentication succeeded"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:accesspoints","type":"wpa_auth","count":"50","device_count":"3","descriptions":"WPA authentication successful"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:securityappliances","type":"content_filtering","count":"10","device_count":"1","descriptions":"Content filtering event"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:securityappliances","type":"dhcp_lease","count":"10","device_count":"1","descriptions":"DHCP lease granted"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:securityappliances","type":"firewall_allow","count":"10","device_count":"1","descriptions":"Firewall rule allowed traffic"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:switches","type":"poe_budget_change","count":"20","device_count":"2","descriptions":"PoE budget updated"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"}]
""")

MERAKI_COMPACT = json.loads(r"""
[{"networkId":"N_KL0000047","sourcetype":"meraki","type":"routine_nominal","count":"120","descriptions":"routine nominal: 6 types, 120 events"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000047","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000112","sourcetype":"meraki","type":"routine_nominal","count":"20","descriptions":"routine nominal: 1 types, 20 events"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:accesspoints","type":"device_offline","count":"10","device_count":"1","descriptions":"Access point is offline — no heartbeat received for 120 seconds"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:accesspoints","type":"wpa_deauth","count":"20","device_count":"1","descriptions":"WPA deauthentication — AP unreachable"},
 {"networkId":"N_KL0000112","sourcetype":"meraki:switches","type":"port_status","count":"10","device_count":"1","descriptions":"Port status changed"},
 {"networkId":"N_KL0000237","sourcetype":"meraki","type":"routine_nominal","count":"120","descriptions":"routine nominal: 6 types, 120 events"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000237","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000305","sourcetype":"meraki","type":"routine_nominal","count":"113","descriptions":"routine nominal: 6 types, 113 events"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:accesspoints","type":"rf_change","count":"9","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000305","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000418","sourcetype":"meraki","type":"routine_nominal","count":"120","descriptions":"routine nominal: 6 types, 120 events"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000418","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"},
 {"networkId":"N_KL0000521","sourcetype":"meraki","type":"routine_nominal","count":"120","descriptions":"routine nominal: 6 types, 120 events"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:accesspoints","type":"rf_change","count":"10","device_count":"1","descriptions":"RF environment changed"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:securityappliances","type":"vpn_registry_change","count":"10","device_count":"1","descriptions":"VPN connectivity change"},
 {"networkId":"N_KL0000521","sourcetype":"meraki:switches","type":"port_status","count":"20","device_count":"2","descriptions":"Port status changed"}]
""")

REFERENCE = {"detect_stores": ["112"], "severity": None}  # detection-only test

FIXTURES = [
    {"id": "06_ap_offline_full", "fault_type": "ap_hardware_failure",
     "description": ("Store 112 AP device_offline (+ wpa_deauth, roamed clients), FULL "
                     "meraki scan (49 rows) — the signal is buried in routine noise. "
                     "Reproduces the live vLLM MISS. Expect detect=112."),
     "previous_alerts": {}, "scan_data": {"sdwan": SDWAN, "te": TE, "meraki": MERAKI_FULL, "ise": ISE},
     "drill_data": {}, "reference": REFERENCE},

    {"id": "07_ap_offline_compact", "fault_type": "ap_hardware_failure",
     "description": ("IDENTICAL to 06 except meraki = SCAN_MERAKI_COMPACT (24 rows): routine "
                     "types collapsed to routine_nominal, device_offline now 1 of 4 rows on 112 "
                     "and the 112 summary reads '1 types' vs '6' on healthy stores. Tests whether "
                     "removing noise alone lets the local model surface device_offline. Expect detect=112."),
     "previous_alerts": {}, "scan_data": {"sdwan": SDWAN, "te": TE, "meraki": MERAKI_COMPACT, "ise": ISE},
     "drill_data": {}, "reference": REFERENCE},
]

for f in FIXTURES:
    (OUT / f"{f['id']}.json").write_text(json.dumps(f, indent=2), encoding="utf-8")
    print("wrote", f["id"],
          "(meraki rows:", len(f["scan_data"]["meraki"]), ")")
print(f"\n{len(FIXTURES)} fixtures in {OUT}")
