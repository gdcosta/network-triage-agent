"""Run the 5 drill queries in parallel for one store. Pure plumbing —
all interpretation of the results happens in the LLM."""
from __future__ import annotations

import asyncio
from typing import Any

import queries
from store import hostname_pattern, ise_device_pattern, network_id_for


async def run_drills(
    client, store: str, site: str, earliest: str, latest: str,
) -> dict[str, list[dict[str, Any]]]:
    hostname = hostname_pattern(store)
    network_id = network_id_for(store)
    device_pattern = ise_device_pattern(store)

    sdwan, te, meraki, ise, timeline = await asyncio.gather(
        client.run_query(queries.drill_sdwan(hostname), earliest, latest),
        client.run_query(queries.drill_te(site), earliest, latest),
        client.run_query(queries.drill_meraki(network_id), earliest, latest),
        client.run_query(queries.drill_ise(device_pattern), earliest, latest),
        client.run_query(
            queries.correlate_timeline(hostname, site, network_id, device_pattern),
            earliest, latest,
        ),
    )

    return {
        "drill_sdwan": sdwan,
        "drill_te": te,
        "drill_meraki": meraki,
        "drill_ise": ise,
        "correlate_timeline": timeline,
    }
