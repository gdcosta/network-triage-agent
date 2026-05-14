"""Polling loop for the Kinetic Leisure network triage agent.

The LLM is the brain. The Python code is the hands and the clock.

Each 30-second cycle:
    1. Scan: run the 4 SPL scan queries in parallel.
    2. Detection LLM call: send scans + previous_alerts. The model
       (with SOUL.md as system prompt) decides which stores need
       correlation drill-downs and which previously-active stores
       have recovered.
    3. Recovery cards: post for any recovered stores.
    4. If correlation requested: run the 5 drill queries per store
       in parallel.
    5. Triage LLM call: send drills + scans + previous_alerts. The
       model produces one triage report per store including its own
       send/skip dedup verdict.
    6. Post AdaptiveCards for reports with action=alert and
       dedup_decision=send.

All output is JSONL on stdout (events + log records). stderr is left
to the runtime for unhandled tracebacks.
"""
from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import events
import queries
from config import Config, load_config
from correlation import run_drills
from llm_client import LLMClient
from splunk_client import SplunkClient
from state import AlertState
from store import city_from_hostname, store_from_hostname
from teams_card import build_card, build_recovery_card, post_card

log = logging.getLogger("triage")

Poster = Callable[[str, dict], Awaitable[None]]


def _city_from_scans(store: str, scan_data: dict[str, list[dict]]) -> str | None:
    """Return the city abbreviation for `store` derived deterministically
    from log data — no LLM inference. Pulls from the SD-WAN scan rows
    where each store has a `vdevice-host-name` like `kl-112-van-rtr-1`.
    Returns None if the store has no SD-WAN data this cycle."""
    for row in scan_data.get("sdwan", []):
        host = row.get("hostname") or ""
        if store_from_hostname(host) == store:
            return city_from_hostname(host)
    return None


def _touch_heartbeat(path: str) -> None:
    """Best-effort liveness marker. The k8s exec probe checks this file's
    age to confirm the poll loop is still turning. Never raises — a failed
    touch must not take down the agent."""
    try:
        Path(path).touch()
    except OSError as exc:
        log.warning("heartbeat touch failed for %s: %s", path, exc)


async def _mock_poster(_url: str, card: dict) -> None:
    body = card.get("body") or [{}]
    header = (body[0].get("items") or [{}])[0].get("text", "")
    events.emit(
        "card.mock_posted",
        version=card.get("version"),
        container_count=len(body),
        action_count=len(card.get("actions") or []),
        header=header,
        card=card,
    )


async def poll_once(
    splunk, llm: LLMClient, cfg: Config, state: AlertState, poster: Poster,
) -> None:
    events.new_cycle()
    cycle_started = time.monotonic()
    events.emit(
        "poll.start",
        earliest=cfg.earliest_time,
        latest=cfg.latest_time,
        active_stores=state.active_stores(),
    )

    # 1. Scan
    sdwan, te, meraki, ise = await asyncio.gather(
        splunk.run_query(queries.SCAN_SDWAN, cfg.earliest_time, cfg.latest_time),
        splunk.run_query(queries.SCAN_TE, cfg.earliest_time, cfg.latest_time),
        splunk.run_query(queries.SCAN_MERAKI, cfg.earliest_time, cfg.latest_time),
        splunk.run_query(queries.SCAN_ISE, cfg.earliest_time, cfg.latest_time),
    )
    scan_data = {"sdwan": sdwan, "te": te, "meraki": meraki, "ise": ise}
    events.emit(
        "scan.complete",
        rows={k: len(v) for k, v in scan_data.items()},
    )

    previous_alerts = state.snapshot()

    # 2. Detection pass
    decision = await llm.detection_pass(
        scan_data=scan_data, previous_alerts=previous_alerts,
    )
    events.emit(
        "detection.decision",
        summary=decision.summary,
        correlate=[s.get("store") for s in decision.correlate_stores],
        recoveries=[s.get("store") for s in decision.recovery_stores],
    )

    # 3. Recovery cards
    if decision.recovery_stores:
        await asyncio.gather(*[
            _send_recovery(rec, state, cfg, poster, scan_data)
            for rec in decision.recovery_stores
        ], return_exceptions=True)

    # 4. Drill in parallel for each correlated store
    if not decision.correlate_stores:
        events.emit(
            "poll.complete",
            duration_ms=int((time.monotonic() - cycle_started) * 1000),
            cards_posted=0,
            recoveries=len(decision.recovery_stores),
        )
        return

    drill_data = await _run_all_drills(splunk, decision.correlate_stores, cfg)

    # 5. Triage pass
    triage = await llm.triage_pass(
        scan_data=scan_data,
        drill_data=drill_data,
        previous_alerts=previous_alerts,
    )

    # 6. Post alert cards according to LLM dedup verdict
    posted = 0
    for report in triage.reports:
        events.emit(
            "triage.report",
            store=report.get("store"),
            action=report.get("action"),
            dedup_decision=report.get("dedup_decision"),
            dedup_rationale=report.get("dedup_rationale"),
            severity=report.get("severity"),
            scope=report.get("scope"),
            root_cause=report.get("root_cause_key"),
            confidence=report.get("confidence"),
            cascade=report.get("cascade_detected"),
            reasoning=report.get("reasoning"),
        )
        if report.get("action") != "alert":
            continue
        if report.get("dedup_decision") != "send":
            continue
        # Override LLM-supplied site with the literal value from logs
        # so store_name is deterministic, not inferred.
        log_city = _city_from_scans(report.get("store", ""), scan_data)
        if log_city:
            report["site"] = log_city
        try:
            card = build_card(
            report, cfg.splunk_base_url, cfg.meraki_base_url, cfg.store_names,
        )
            await poster(cfg.teams_webhook_url, card)
            state.record_sent(report)
            events.emit(
                "card.posted",
                store=report.get("store"),
                severity=report.get("severity"),
                scope=report.get("scope"),
            )
            posted += 1
        except Exception as exc:
            events.emit(
                "card.failed",
                store=report.get("store"),
                error=type(exc).__name__,
                message=str(exc)[:200],
            )
            log.exception("card POST failed for store %s", report.get("store"))

    events.emit(
        "poll.complete",
        duration_ms=int((time.monotonic() - cycle_started) * 1000),
        cards_posted=posted,
        recoveries=len(decision.recovery_stores),
    )


async def _run_all_drills(splunk, correlate_stores: list[dict], cfg: Config) -> dict:
    async def _one(spec: dict) -> tuple[str, dict]:
        store = spec.get("store", "")
        site = spec.get("site", "")
        events.emit("correlation.start", store=store, site=site, reason=spec.get("reason"))
        drills = await run_drills(splunk, store, site, cfg.earliest_time, cfg.latest_time)
        events.emit(
            "correlation.complete", store=store,
            drill_rows={k: len(v) for k, v in drills.items()},
        )
        return store, drills

    pairs = await asyncio.gather(*[_one(s) for s in correlate_stores], return_exceptions=False)
    return {store: drills for store, drills in pairs}


async def _send_recovery(
    rec: dict, state: AlertState, cfg: Config, poster: Poster,
    scan_data: dict[str, list[dict]] | None = None,
) -> None:
    store = rec.get("store", "")
    prev = state.clear(store)
    duration_min = None
    if prev is not None:
        duration_min = (datetime.now(timezone.utc) - prev.first_seen).total_seconds() / 60.0
    payload = {**rec, "duration_minutes": duration_min,
               "timestamp": datetime.now(timezone.utc).isoformat()}
    log_city = _city_from_scans(store, scan_data or {})
    if log_city:
        payload["site"] = log_city
    try:
        card = build_recovery_card(
            payload, cfg.splunk_base_url, cfg.meraki_base_url, cfg.store_names,
        )
        await poster(cfg.teams_webhook_url, card)
        events.emit(
            "recovery.posted", store=store, site=rec.get("site"),
            recovered_domains=rec.get("recovered_domains"),
            duration_minutes=duration_min,
        )
    except Exception as exc:
        events.emit(
            "recovery.failed", store=store,
            error=type(exc).__name__, message=str(exc)[:200],
        )
        log.exception("recovery webhook failed for store %s", store)


async def run(mock: bool = False) -> None:
    cfg = load_config(mock=mock)
    state = AlertState()
    stop_event = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_event.set)

    events.emit(
        "agent.start",
        mode="mock" if mock else "live",
        model=cfg.llm_model,
        soul_path=cfg.soul_path,
        poll_interval_seconds=cfg.poll_interval_seconds,
        earliest=cfg.earliest_time,
        latest=cfg.latest_time,
    )
    # Mark liveness immediately so the probe has a fresh file before the
    # first (potentially slow) poll cycle finishes.
    _touch_heartbeat(cfg.heartbeat_file)

    if mock:
        from mock_splunk import MockSplunkClient
        splunk_cm = MockSplunkClient()
        poster: Poster = _mock_poster
    else:
        splunk_cm = SplunkClient(
            cfg.splunk_mcp_command, cfg.splunk_mcp_args,
            cfg.splunk_tool_name, cfg.splunk_row_limit,
            env=cfg.splunk_mcp_env,
        )
        poster = post_card

    use_mock_llm = mock and cfg.anthropic_api_key in ("", "mock")
    if use_mock_llm:
        from mock_llm import MockLLMClient
        llm = MockLLMClient()
        events.emit("llm.mode", mode="mock",
                    reason="--mock with no ANTHROPIC_API_KEY; scripted responses")
    else:
        llm = LLMClient(
            api_key=cfg.anthropic_api_key,
            model=cfg.llm_model,
            soul_path=cfg.soul_path,
        )

    async with splunk_cm as splunk:
        while not stop_event.is_set():
            try:
                await poll_once(splunk, llm, cfg, state, poster)
            except Exception as exc:
                events.emit(
                    "poll.failed",
                    error=type(exc).__name__,
                    message=str(exc)[:300],
                )
                log.exception("poll cycle failed")
            # Heartbeat after every cycle attempt — success or handled
            # failure — so the probe tracks "loop is turning", not "loop
            # is succeeding". A hung poll_once lets the file go stale.
            _touch_heartbeat(cfg.heartbeat_file)
            if mock and hasattr(splunk, "advance"):
                splunk.advance()
            if use_mock_llm and hasattr(llm, "cycle"):
                llm.cycle = splunk.cycle if hasattr(splunk, "cycle") else (llm.cycle + 1)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=cfg.poll_interval_seconds)
            except asyncio.TimeoutError:
                pass

    events.emit("agent.stop", active_stores=state.active_stores())


async def preflight() -> int:
    """Verify config + LLM API + Splunk MCP independently, print pass/fail.
    Plain text on stdout so it's easy to read interactively."""
    print("Preflight checks for the Kinetic Leisure triage agent")
    print("=" * 60)

    try:
        cfg = load_config()
    except RuntimeError as e:
        print(f"  ✗ config: {e}")
        return 1

    print("Config:")
    print(f"  LLM model:       {cfg.llm_model}")
    print(f"  SOUL prompt:     {cfg.soul_path}")
    print(f"  Splunk MCP cmd:  {cfg.splunk_mcp_command} {' '.join(cfg.splunk_mcp_args[:3])}"
          + (" ..." if len(cfg.splunk_mcp_args) > 3 else ""))
    print(f"  Splunk tool:     {cfg.splunk_tool_name}")
    print(f"  Splunk window:   earliest={cfg.earliest_time}  latest={cfg.latest_time}")
    print(f"  Teams webhook:   {cfg.teams_webhook_url[:50]}{'...' if len(cfg.teams_webhook_url) > 50 else ''}")
    print()

    failures: list[str] = []

    # --- 1. SOUL.md
    print("[1/3] SOUL.md system prompt")
    soul_path = Path(cfg.soul_path)
    if not soul_path.is_file():
        print(f"      ✗ not found at {soul_path.resolve()}")
        failures.append("soul")
    else:
        size = soul_path.stat().st_size
        # Rough token count: ~4 chars per token
        approx_tokens = soul_path.read_text(encoding="utf-8").__len__() // 4
        print(f"      ✓ {soul_path} — {size} bytes (~{approx_tokens} tokens)")
    print()

    # --- 2. Anthropic API
    print("[2/3] Anthropic API")
    try:
        from anthropic import AsyncAnthropic
        client = AsyncAnthropic(api_key=cfg.anthropic_api_key)
        resp = await client.messages.create(
            model=cfg.llm_model,
            max_tokens=20,
            messages=[{"role": "user", "content": "Reply with just the word: ok"}],
        )
        text = "".join(getattr(b, "text", "") for b in resp.content).strip()
        print(f"      ✓ {cfg.llm_model} responded: {text!r}")
        print(f"      ✓ tokens in/out: {resp.usage.input_tokens}/{resp.usage.output_tokens}")
    except Exception as e:
        print(f"      ✗ {type(e).__name__}: {e}")
        failures.append("llm")
    print()

    # --- 3. Splunk MCP
    print("[3/3] Splunk MCP")
    try:
        async with SplunkClient(
            cfg.splunk_mcp_command, cfg.splunk_mcp_args,
            cfg.splunk_tool_name, cfg.splunk_row_limit,
            env=cfg.splunk_mcp_env,
        ) as splunk:
            tools_result = await splunk._session.list_tools()
            tool_names = [t.name for t in tools_result.tools]
            print(f"      ✓ MCP session initialized; {len(tool_names)} tools available")

            if cfg.splunk_tool_name not in tool_names:
                print(f"      ✗ configured tool '{cfg.splunk_tool_name}' NOT in available tools")
                print(f"        available: {', '.join(tool_names)}")
                failures.append("splunk_tool_missing")
            else:
                print(f"      ✓ '{cfg.splunk_tool_name}' is exposed")

                # Trivial query — | makeresults generates a row without touching data.
                rows = await splunk.run_query("| makeresults count=1", "-1m", "now")
                print(f"      ✓ trivial query returned {len(rows)} row(s)")
    except Exception as e:
        print(f"      ✗ {type(e).__name__}: {e}")
        failures.append("splunk")
    print()

    if failures:
        print(f"FAILED: {len(failures)} check(s) failed: {', '.join(failures)}")
        return 1
    print("All checks passed. Run `python main.py` to start the agent.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Kinetic Leisure network triage agent")
    parser.add_argument(
        "--mock", action="store_true",
        help="Use canned Splunk data and stub the Teams webhook (LLM still real if API key set).",
    )
    parser.add_argument(
        "--check", action="store_true",
        help="Run preflight: verify config + Anthropic API + Splunk MCP connection, then exit.",
    )
    args = parser.parse_args()
    if args.check:
        sys.exit(asyncio.run(preflight()))
    events.init_logging()
    asyncio.run(run(mock=args.mock))


if __name__ == "__main__":
    main()
