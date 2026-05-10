"""SPL query strings, copied verbatim from SOUL.md.

Scan queries run every poll cycle; drill queries run per-store after a
detection trigger. The trailing kl:scenario_controller exclusion matches
SOUL's "ignore internal test tooling" rule.
"""
from __future__ import annotations

_EXCLUDE_SCENARIO = ' NOT sourcetype="kl:scenario_controller:log"'


SCAN_SDWAN = (
    'index=main sourcetype IN ("cisco:sdwan:tunnelhealth","cisco:sdwan:sitehealth")'
    + _EXCLUDE_SCENARIO + r"""
| spath output=hostname path=vdevice-host-name
| spath output=state path=state
| spath output=site_health path=site-health
| spath output=color path=local_color
| spath output=jitter path=jitter
| spath output=latency path=latency
| spath output=loss path=loss
| spath output=vqoe path=vqoe_score
| spath output=bfd_up path=bfd-sessions-up
| spath output=bfd_down path=bfd-sessions-down
| spath output=device_status path=device-status
| spath output=reachability path=reachability
| stats latest(site_health) AS site_health,
    latest(device_status) AS device_status,
    latest(reachability) AS reachability,
    latest(bfd_up) AS bfd_up,
    latest(bfd_down) AS bfd_down,
    values(state) AS tunnel_states,
    values(color) AS transports,
    avg(jitter) AS avg_jitter,
    avg(latency) AS avg_latency,
    max(loss) AS max_loss,
    min(vqoe) AS min_vqoe
  by hostname
""")


SCAN_TE = (
    'index=main sourcetype IN ("cisco:thousandeyes:alerts",'
    '"cisco:thousandeyes:pathtrace","cisco:thousandeyes:bgp")'
    + _EXCLUDE_SCENARIO + r"""
| spath output=alertState path=alertState
| spath output=active path=active
| spath output=severity path=severity
| spath output=testName path=testName
| spath output=site path=site
| spath output=responseTime path=metricsAtStart.responseTime
| spath output=packetLoss path=metricsAtStart.packetLoss
| spath output=jitter path=metricsAtStart.jitter
| spath output=ispStatus path=ispStatus
| spath output=edgeStatus path=enterpriseEdgeStatus
| spath output=conclusion path=conclusion
| spath output=bgp_status path=status
| spath output=reachPct path=reachabilityPct
| spath output=pathChanges path=pathChanges
| stats latest(alertState) AS alert_cleared,
    latest(severity) AS severity,
    avg(responseTime) AS avg_resp_ms,
    max(responseTime) AS max_resp_ms,
    max(packetLoss) AS max_loss_pct,
    max(jitter) AS max_jitter,
    latest(ispStatus) AS isp_status,
    latest(edgeStatus) AS edge_status,
    latest(conclusion) AS path_conclusion,
    latest(bgp_status) AS bgp_status,
    latest(reachPct) AS bgp_reach_pct,
    sum(pathChanges) AS bgp_path_changes
  by site
""")


SCAN_MERAKI = (
    'index=main sourcetype IN ("meraki:accesspoints",'
    '"meraki:switches","meraki:securityappliances")'
    + _EXCLUDE_SCENARIO + r"""
| spath output=type path=type
| spath output=networkId path=networkId
| spath output=deviceName path=deviceName
| spath output=description path=description
| stats count, dc(deviceName) AS device_count,
    values(description) AS descriptions
  by networkId, sourcetype, type
| sort networkId, sourcetype, type
""")


SCAN_ISE = (
    'index=main sourcetype="cisco:ise:syslog"'
    + _EXCLUDE_SCENARIO + r"""
| rex "(?P<ise_event>CISE_\w+)"
| rex "NAS-IP-Address=(?P<nas_ip>[^,]+)"
| rex "NetworkDeviceName=(?P<device_name>[^,]+)"
| rex "UserName=(?P<user>[^,]+)"
| stats count, dc(user) AS unique_users,
    values(nas_ip) AS nas_ips
  by ise_event, device_name
| sort device_name, ise_event
""")


_DRILL_SDWAN = r"""index=main sourcetype IN ("cisco:sdwan:tunnelhealth","cisco:sdwan:sitehealth")
| spath output=hostname path=vdevice-host-name
| search hostname="{hostname}"
| spath output=state path=state
| spath output=site_health path=site-health
| spath output=color path=local_color
| spath output=jitter path=jitter
| spath output=latency path=latency
| spath output=loss path=loss
| spath output=vqoe path=vqoe_score
| spath output=bfd_up path=bfd-sessions-up
| spath output=bfd_down path=bfd-sessions-down
| spath output=reachability path=reachability
| stats latest(state) AS tunnel_state,
    latest(jitter) AS jitter_ms,
    latest(latency) AS latency_ms,
    latest(loss) AS loss_pct,
    latest(vqoe) AS vqoe,
    earliest(_time) AS first_seen,
    latest(_time) AS last_seen,
    count AS event_count
  by color
| append
  [search index=main sourcetype="cisco:sdwan:sitehealth"
  | spath output=hostname path=vdevice-host-name
  | search hostname="{hostname}"
  | spath output=site_health path=site-health
  | spath output=bfd_up path=bfd-sessions-up
  | spath output=bfd_down path=bfd-sessions-down
  | spath output=reachability path=reachability
  | stats latest(site_health) AS site_health,
      latest(bfd_up) AS bfd_up,
      latest(bfd_down) AS bfd_down,
      latest(reachability) AS reachability
  | eval color="SITE_SUMMARY"]
"""


_DRILL_TE = r"""index=main sourcetype IN ("cisco:thousandeyes:alerts","cisco:thousandeyes:pathtrace")
| spath output=site path=site
| search site="{site}"
| spath output=alertState path=alertState
| spath output=severity path=severity
| spath output=testName path=testName
| spath output=responseTime path=metricsAtStart.responseTime
| spath output=packetLoss path=metricsAtStart.packetLoss
| spath output=jitter path=metricsAtStart.jitter
| spath output=ispStatus path=ispStatus
| spath output=edgeStatus path=enterpriseEdgeStatus
| spath output=conclusion path=conclusion
| spath output=problemHop path=problemHop
| spath output=problemNode path=problemNode
| spath output=hopLatency path=hopLatencyMs
| stats latest(alertState) AS alert_cleared,
    latest(severity) AS severity,
    avg(responseTime) AS avg_resp_ms,
    max(responseTime) AS max_resp_ms,
    latest(packetLoss) AS last_loss,
    latest(jitter) AS last_jitter,
    latest(ispStatus) AS isp_status,
    latest(edgeStatus) AS edge_status,
    latest(conclusion) AS conclusion,
    latest(problemHop) AS problem_hop,
    latest(problemNode) AS problem_node,
    latest(hopLatency) AS hop_latency_ms,
    count AS events
  by sourcetype
"""


_DRILL_MERAKI = r"""index=main sourcetype IN ("meraki:accesspoints","meraki:switches","meraki:securityappliances")
| spath output=networkId path=networkId
| search networkId="{network_id}"
| spath output=type path=type
| spath output=deviceName path=deviceName
| spath output=description path=description
| spath output=clientDesc path=eventData.identity
| spath output=vpn_conn path=eventData.connectivity
| spath output=vpn_peer path=eventData.peer
| stats count,
    dc(deviceName) AS device_count,
    values(deviceName) AS devices,
    values(description) AS descriptions,
    latest(clientDesc) AS sample_client,
    latest(vpn_conn) AS vpn_state,
    latest(vpn_peer) AS vpn_peer
  by sourcetype, type
| sort sourcetype, type
"""


_DRILL_ISE = r"""index=main sourcetype="cisco:ise:syslog" "{device_pattern}"
| rex "(?P<ise_event>CISE_\w+)"
| rex "NetworkDeviceName=(?P<device_name>[^,]+)"
| rex "UserName=(?P<user>[^,]+)"
| rex "NAS-IP-Address=(?P<nas_ip>[^,]+)"
| rex "Framed-IP-Address=(?P<framed_ip>[^,]+)"
| stats count,
    dc(nas_ip) AS nas_count,
    values(nas_ip) AS nas_ips
  by ise_event, user
| sort ise_event, -count
"""


_CORRELATE_TIMELINE = r"""index=main
  ((sourcetype IN ("cisco:sdwan:tunnelhealth","cisco:sdwan:sitehealth") "{hostname}")
  OR (sourcetype IN ("cisco:thousandeyes:alerts","cisco:thousandeyes:pathtrace") "{site}")
  OR (sourcetype IN ("meraki:accesspoints","meraki:switches","meraki:securityappliances") "{network_id}")
  OR (sourcetype="cisco:ise:syslog" "{device_pattern}"))
| eval domain=case(
    match(sourcetype,"cisco:sdwan"),"SDWAN",
    match(sourcetype,"cisco:thousandeyes"),"TE",
    match(sourcetype,"meraki:"),"MERAKI",
    match(sourcetype,"cisco:ise"),"ISE",
    1=1,"OTHER")
| spath output=state path=state
| spath output=color path=local_color
| spath output=site_health path=site-health
| spath output=jitter path=jitter
| spath output=latency path=latency
| spath output=loss path=loss
| spath output=vqoe path=vqoe_score
| spath output=bfd_down path=bfd-sessions-down
| spath output=reachability path=reachability
| spath output=type path=type
| spath output=deviceName path=deviceName
| spath output=description path=description
| spath output=alertState path=alertState
| spath output=severity path=severity
| spath output=responseTime path=metricsAtStart.responseTime
| spath output=packetLoss path=metricsAtStart.packetLoss
| spath output=ispStatus path=ispStatus
| spath output=edgeStatus path=enterpriseEdgeStatus
| spath output=conclusion path=conclusion
| rex "(?P<ise_event>CISE_\w+)"
| rex "UserName=(?P<user>[^,]+)"
| eval detail=case(
    domain="SDWAN" AND isnotnull(color),
      color." tunnel ".state." | jitter=".jitter."ms lat=".latency."ms loss=".loss." vqoe=".vqoe,
    domain="SDWAN" AND isnotnull(site_health),
      "site=".site_health." bfd_down=".bfd_down." reach=".reachability,
    domain="TE" AND isnotnull(alertState),
      "alert_cleared=".alertState." sev=".severity." resp=".responseTime."ms loss=".packetLoss,
    domain="TE" AND isnotnull(ispStatus),
      "path: isp=".ispStatus." edge=".edgeStatus." | ".conclusion,
    domain="MERAKI",
      type." on ".deviceName." | ".description,
    domain="ISE",
      ise_event." user=".user,
    1=1, "raw")
| table _time, domain, sourcetype, detail
| sort _time
"""


def drill_sdwan(hostname: str) -> str:
    return _DRILL_SDWAN.format(hostname=hostname)


def drill_te(site: str) -> str:
    return _DRILL_TE.format(site=site)


def drill_meraki(network_id: str) -> str:
    return _DRILL_MERAKI.format(network_id=network_id)


def drill_ise(device_pattern: str) -> str:
    return _DRILL_ISE.format(device_pattern=device_pattern)


def correlate_timeline(hostname: str, site: str, network_id: str, device_pattern: str) -> str:
    return _CORRELATE_TIMELINE.format(
        hostname=hostname,
        site=site,
        network_id=network_id,
        device_pattern=device_pattern,
    )
