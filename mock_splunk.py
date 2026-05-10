"""MockSplunkClient — a stand-in for SplunkClient that returns canned
data from a scripted scenario. Lets you run the full polling loop end
to end without a real Splunk MCP server.

The script rotates through 6 cycles and then loops, demonstrating:
    cycle 0: healthy fleet — silence (no card)
    cycle 1: store 237 MPLS tunnel down — P1 CRITICAL + cascade
    cycle 2: same state — dedup suppresses (but events still fire)
    cycle 3: TE degrades too — new domain → re-send
    cycle 4: recovered — RESOLVED card
    cycle 5: healthy again — silence
    (loops)
"""
from __future__ import annotations

from typing import Any

# ---------- canned scan rows ----------

_STORES = ("237", "101", "150")
_CITIES = {"237": "portland", "101": "seattle", "150": "tacoma"}


def _healthy_sdwan() -> list[dict]:
    return [
        {"hostname": f"kl-{s}-{_CITIES[s]}-rtr-1",
         "site_health": "good", "reachability": "reachable",
         "device_status": "Normal",
         "bfd_down": 0, "bfd_up": 4,
         "tunnel_states": ["up", "up"], "transports": ["mpls", "lte"],
         "avg_jitter": 5.0 + i, "avg_latency": 30.0 + i, "max_loss": 0,
         "min_vqoe": 9.5}
        for i, s in enumerate(_STORES)
    ]


def _healthy_te() -> list[dict]:
    return [
        {"site": _CITIES[s], "alert_cleared": "true", "severity": "INFO",
         "avg_resp_ms": 80 + i, "max_resp_ms": 100, "max_loss_pct": 0,
         "max_jitter": 5,
         "isp_status": "healthy", "edge_status": "healthy",
         "path_conclusion": "healthy",
         "bgp_status": "established", "bgp_reach_pct": 100,
         "bgp_path_changes": 0,
         "agentName": f"kl-te-{_CITIES[s]}-{s}.example.com"}
        for i, s in enumerate(_STORES)
    ]


def _healthy_meraki() -> list[dict]:
    out = []
    for s in _STORES:
        out.extend([
            {"networkId": f"N_KL0000{s}", "sourcetype": "meraki:accesspoints",
             "type": "wpa_auth", "count": 50, "device_count": 3,
             "descriptions": ["client connect"]},
            {"networkId": f"N_KL0000{s}", "sourcetype": "meraki:switches",
             "type": "port_status", "count": 30, "device_count": 2,
             "descriptions": ["port up"]},
            {"networkId": f"N_KL0000{s}", "sourcetype": "meraki:securityappliances",
             "type": "dhcp_lease", "count": 20, "device_count": 1,
             "descriptions": ["dhcp ack"]},
        ])
    return out


def _healthy_ise() -> list[dict]:
    return [
        {"ise_event": "CISE_Passed_Authentications",
         "device_name": f"KL-{s}-AP", "count": 100, "unique_users": 5,
         "nas_ips": [f"10.10.{int(s)}.1"]}
        for s in _STORES
    ]


def _wan_down_237(sdwan: list[dict]) -> list[dict]:
    out = [dict(r) for r in sdwan]
    out[0] = {**out[0],
              "tunnel_states": ["down", "up"],
              "site_health": "degraded",
              "bfd_down": 1, "bfd_up": 3,
              "max_loss": 2.5, "min_vqoe": 1.8,
              "avg_jitter": 95.0, "avg_latency": 180.0}
    return out


def _te_degraded_237(te: list[dict]) -> list[dict]:
    out = [dict(r) for r in te]
    out[0] = {**out[0],
              "alert_cleared": "false", "severity": "MAJOR",
              "avg_resp_ms": 720, "max_resp_ms": 850,
              "max_loss_pct": 3.0,
              "isp_status": "degraded",
              "path_conclusion": "ISP-side packet loss"}
    return out


# ---------- canned drill rows ----------

def _drill_sdwan_237_down() -> list[dict]:
    return [
        {"color": "mpls", "tunnel_state": "down",
         "jitter_ms": 95, "latency_ms": 180, "loss_pct": 2.5, "vqoe": 1.8,
         "first_seen": 1746000000, "last_seen": 1746000060, "event_count": 5},
        {"color": "lte", "tunnel_state": "up",
         "jitter_ms": 12, "latency_ms": 80, "loss_pct": 0, "vqoe": 8.0,
         "first_seen": 1746000000, "last_seen": 1746000060, "event_count": 5},
        {"color": "SITE_SUMMARY", "site_health": "degraded",
         "bfd_up": 3, "bfd_down": 1, "reachability": "reachable"},
    ]


def _drill_te_237_degraded() -> list[dict]:
    return [
        {"sourcetype": "cisco:thousandeyes:alerts",
         "alert_cleared": "false", "severity": "MAJOR",
         "avg_resp_ms": 720, "max_resp_ms": 850,
         "last_loss": 3.0, "last_jitter": 15,
         "isp_status": "degraded", "edge_status": "healthy",
         "conclusion": "ISP-side packet loss",
         "problem_node": "comcast-pdx-core-3", "events": 4},
    ]


def _drill_meraki_237_quiet() -> list[dict]:
    return [
        {"sourcetype": "meraki:accesspoints", "type": "wpa_auth",
         "count": 8, "device_count": 3,
         "devices": ["KL-237-PDX-AP1", "KL-237-PDX-AP2", "KL-237-PDX-AP3"],
         "descriptions": ["client reauth"]},
    ]


def _timeline_sdwan_first() -> list[dict]:
    return [
        {"_time": 1746000000, "domain": "SDWAN",
         "sourcetype": "cisco:sdwan:tunnelhealth",
         "detail": "mpls tunnel down"},
        {"_time": 1746000020, "domain": "TE",
         "sourcetype": "cisco:thousandeyes:alerts",
         "detail": "alert_cleared=false sev=MAJOR"},
        {"_time": 1746000040, "domain": "MERAKI",
         "sourcetype": "meraki:accesspoints",
         "detail": "wpa_auth client disconnect"},
    ]


# ---------- the client ----------

class MockSplunkClient:
    """Behaves like SplunkClient but returns scripted rows."""

    def __init__(self) -> None:
        self.cycle = 0

    async def __aenter__(self) -> "MockSplunkClient":
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def run_query(
        self, spl: str, earliest_time: str, latest_time: str
    ) -> list[dict[str, Any]]:
        kind = _classify(spl)
        scenario = self.cycle % 6

        # NB: cycle is incremented after the SDWAN scan is requested, so
        # all 4 scans + drills within one poll see the same scenario.
        if kind in ("scan_sdwan", "scan_te", "scan_meraki", "scan_ise"):
            return _scan_for(scenario, kind)
        if kind in ("drill_sdwan", "drill_te", "drill_meraki", "drill_ise", "timeline"):
            return _drill_for(scenario, kind)
        return []

    def advance(self) -> None:
        """Call once per poll cycle from the harness so scenarios rotate."""
        self.cycle += 1


# ---------- dispatch helpers ----------

def _classify(spl: str) -> str:
    s = spl
    if "eval domain=case" in s:
        return "timeline"
    if 'sourcetype IN ("cisco:sdwan:' in s and "search hostname=" in s:
        return "drill_sdwan"
    if 'sourcetype IN ("cisco:thousandeyes:' in s and "search site=" in s:
        return "drill_te"
    if 'sourcetype IN ("meraki:' in s and "search networkId=" in s:
        return "drill_meraki"
    if 'sourcetype="cisco:ise:syslog"' in s and 'sourcetype="cisco:ise:syslog"\n' not in s and "by ise_event, device_name" not in s:
        return "drill_ise"
    if 'sourcetype IN ("cisco:sdwan:' in s:
        return "scan_sdwan"
    if 'sourcetype IN ("cisco:thousandeyes:' in s:
        return "scan_te"
    if 'sourcetype IN ("meraki:' in s:
        return "scan_meraki"
    if 'sourcetype="cisco:ise:syslog"' in s:
        return "scan_ise"
    return "unknown"


def _scan_for(scenario: int, kind: str) -> list[dict]:
    # 0=healthy  1=WAN-down  2=WAN-down(persist)  3=WAN+TE  4=recovered  5=healthy
    sdwan = _healthy_sdwan()
    te = _healthy_te()
    meraki = _healthy_meraki()
    ise = _healthy_ise()

    if scenario in (1, 2):
        sdwan = _wan_down_237(sdwan)
    elif scenario == 3:
        sdwan = _wan_down_237(sdwan)
        te = _te_degraded_237(te)

    return {"scan_sdwan": sdwan, "scan_te": te,
            "scan_meraki": meraki, "scan_ise": ise}[kind]


def _drill_for(scenario: int, kind: str) -> list[dict]:
    if scenario in (1, 2, 3):
        return {
            "drill_sdwan": _drill_sdwan_237_down(),
            "drill_te": _drill_te_237_degraded() if scenario == 3 else [],
            "drill_meraki": _drill_meraki_237_quiet(),
            "drill_ise": [],
            "timeline": _timeline_sdwan_first(),
        }[kind]
    return []
