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
import json
import logging
import os
import signal
import sys
import time
from contextlib import AsyncExitStack
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import events
import mcp_inspect
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


async def _start_state_server(state: AlertState, port: int) -> Any:
    """Start a small HTTP server exposing the agent's AlertState as JSON.

    Opt-in via AGENT_STATE_PORT env var (default 0 = disabled). Used by the
    triage_mcp service to answer "what is the agent currently working on?"
    questions from the chat bot in real time. Returns the aiohttp AppRunner
    so the caller can clean it up on shutdown.

    The endpoint is intentionally narrow:
      GET /state  → {cycle_id, updated_at, snapshot: {store: {...}, ...}}
      GET /health → {ok: true}
    No auth — relies on Cilium NetworkPolicy + WireGuard for in-cluster
    confidentiality + access control.
    """
    from aiohttp import web

    async def get_state(_request: web.Request) -> web.Response:
        cycle_id, started_at = events.latest_cycle()
        return web.json_response({
            "cycle_id": cycle_id or None,
            "updated_at": started_at.isoformat() if started_at else None,
            "snapshot": state.snapshot(),
        })

    async def get_health(_request: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    app = web.Application()
    app.router.add_get("/state", get_state)
    app.router.add_get("/health", get_health)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    events.emit("agent.state_server.start", port=port, paths=["/state", "/health"])
    return runner


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


async def _rehydrate_history(history, cfg: Config, state: AlertState) -> None:
    """Task #56 stage 1: read the agent's OWN past triage.report outcomes back
    from triage-mcp at startup, so a restarted pod isn't blind to recent history.

    Stashes the events on state.startup_history (read-only context for stage 2);
    deliberately does NOT mutate the open-alert set. Fail-open at every step —
    history is enrichment, never a gate, so a triage-mcp/inspect hiccup must not
    stop the agent from starting its loop.
    """
    args: dict[str, Any] = {"hours": cfg.history_lookback_hours}

    # Tier #2: inspect our own outbound call at the agent boundary before it
    # leaves the pod (triage-mcp's sidecar inspects the resulting SPL on its end).
    verdict = await mcp_inspect.inspect_tool(cfg.history_mcp_tool, args)
    if mcp_inspect.is_blocked(verdict):
        events.emit("history.rehydrate_blocked", reason=verdict.get("reason"),
                    severity=verdict.get("severity"), mode=verdict.get("mode"))
        return

    try:
        payload = await history.call_tool(args)
    except Exception as exc:
        events.emit("history.rehydrate_failed",
                    error=type(exc).__name__, message=str(exc)[:200])
        return

    if isinstance(payload, dict) and payload.get("error"):
        events.emit("history.rehydrate_error", error=payload.get("error"),
                    detail=str(payload.get("reason") or payload.get("detail") or "")[:200])
        return

    evts = payload.get("events", []) if isinstance(payload, dict) else []
    state.startup_history = [e for e in evts if isinstance(e, dict)]
    events.emit("history.rehydrated",
                event_count=len(state.startup_history),
                hours=cfg.history_lookback_hours,
                inspect_mode=verdict.get("mode") or verdict.get("action"))


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
    # Guard B: a store cannot be both recovered AND actively alerting in the same
    # cycle. If detection lists a store in BOTH correlate_stores and
    # recovery_stores, that's self-contradictory — trust the active alert and drop
    # the recovery. Without this, a still-critical store flaps: recovery card +
    # P1 card every cycle (observed 2026-06-03 on store 305, still hard-down).
    # Deterministic; the alert wins over the LLM's contradictory recovery claim.
    correlating = {s.get("store") for s in decision.correlate_stores}
    recoveries = [r for r in decision.recovery_stores
                  if r.get("store") not in correlating]
    for store in (r.get("store") for r in decision.recovery_stores
                  if r.get("store") in correlating):
        events.emit("recovery.suppressed", store=store, reason="also_correlating")
    if recoveries:
        await asyncio.gather(*[
            _send_recovery(rec, state, cfg, poster, scan_data)
            for rec in recoveries
        ], return_exceptions=True)

    # 4. Drill in parallel for each correlated store
    if not decision.correlate_stores:
        events.emit(
            "poll.complete",
            duration_ms=int((time.monotonic() - cycle_started) * 1000),
            cards_posted=0,
            recoveries=len(recoveries),
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
        # An alert card must carry a real severity tier (P1/P2/P3). The triage LLM
        # sometimes emits severity="RESOLVED" on the ALERT path during a store's
        # recovery transition (observed 2026-06-03 on 418/047). A real recovery
        # must come through the recovery path (recovery_stores -> recovery.posted),
        # never as an alert card — so suppress non-tier severities to stop a
        # premature "RESOLVED" leaking out the alert channel. (Task #66.)
        # An alert card must carry a real severity tier (P1/P2/P3). The triage LLM
        # sometimes emits severity="RESOLVED" on the ALERT path during a store's
        # recovery transition (observed 2026-06-03 on 418/047). A real recovery
        # must come through the recovery path (recovery_stores -> recovery.posted),
        # never as an alert card — so suppress non-tier severities to stop a
        # premature "RESOLVED" leaking out the alert channel. (Task #66.)
        # NB: converting RESOLVED -> immediate recovery (option c) was tried and
        # reverted 2026-06-04 — it cleared state before the -5m scan window aged
        # out, so the detection pass re-flagged the store as a fresh fault (P2
        # re-alert flap on 521). Recovery stays on the detection pass, which waits
        # for the window to clear and so can't re-alert.
        sev = (report.get("severity") or "").strip().upper()
        if not sev.startswith(("P1", "P2", "P3")):
            events.emit(
                "triage.nonalert_suppressed",
                store=report.get("store"),
                severity=report.get("severity"),
                reason="not_a_p_tier",
            )
            continue
        # Severity hysteresis (task #66): escalate fast, de-escalate slow. Damps
        # the LLM flapping a stable incident's tier (observed P1<->P2 on store 305,
        # 2026-06-04). A downgrade is held at the confirmed tier until the lower
        # tier persists a few cycles; escalations apply at once. The card uses the
        # held severity; the raw LLM value is preserved in the triage.report event
        # above. When held, the severity matches the confirmed tier, so the dedup
        # backstop below suppresses the (now-duplicate) card.
        proposed_sev = report.get("severity")
        held_sev = state.effective_severity(report.get("store", ""), proposed_sev or "")
        if held_sev != proposed_sev:
            events.emit(
                "severity.held",
                store=report.get("store"),
                proposed=proposed_sev,
                held_at=held_sev,
            )
            report["severity"] = held_sev
        if report.get("dedup_decision") != "send":
            continue
        # Deterministic dedup backstop (task #66): even when the LLM says "send",
        # suppress a card whose (severity, scope, root_cause_key, domains_affected)
        # all match the store's last-sent state. Model-proof — Haiku cannot spam an
        # unchanged incident no matter how it rationalizes the re-send. SOUL.md
        # tightening reduces the rate; this makes it airtight. Mirrors guard B.
        if state.is_unchanged(report):
            events.emit(
                "triage.dedup_suppressed",
                store=report.get("store"),
                severity=report.get("severity"),
                scope=report.get("scope"),
                root_cause=report.get("root_cause_key"),
                llm_decision=report.get("dedup_decision"),
            )
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
        recoveries=len(recoveries),
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
    # Guard A: you can't recover what was never open. If the LLM names a store in
    # recovery_stores that has no open alert in AlertState (prev is None), it's a
    # phantom recovery — suppress it. Without this, a single hallucinated
    # recovery_stores list posts "resolved" cards for healthy, never-alerted
    # stores (observed 2026-06-03: 5 healthy stores resolved in one cycle while
    # store 305 was still hard-down). Deterministic; independent of LLM judgment.
    if prev is None:
        events.emit("recovery.suppressed", store=store, reason="no_open_alert")
        return
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


def _bootstrap_defenseclaw_proxy_headers(wait_seconds: int = 60) -> None:
    """Task #55: make the agent's Anthropic SDK calls authenticate to the
    local DefenseClaw guardrail proxy.

    When ANTHROPIC_BASE_URL points at the sidecar proxy (http://127.0.0.1:4000),
    every /v1/messages call is intercepted by DefenseClaw's openclaw connector.
    That connector authenticates each hop via `X-DC-Auth: Bearer <gateway-token>`
    and learns the real upstream from `X-DC-Target-URL` — the exact headers
    OpenClaw's fetch-interceptor plugin injects for the bot (DefenseClaw
    extensions/defenseclaw/src/fetch-interceptor.ts :: buildProxyHeaders). Our
    plain AsyncAnthropic doesn't speak that dialect, so without these headers
    the proxy rejects with AUTH_MISSING_TOKEN — surfaced to the SDK as a
    synthetic 401 invalid_api_key. We set both via ANTHROPIC_CUSTOM_HEADERS,
    which the SDK parses natively. The agent's own x-api-key passes through
    untouched as the upstream provider key (the connector reads it via
    ExtractAPIKey and strips the X-DC-* headers before forwarding upstream).

    The gateway token is written by the sidecar to a shared in-memory volume
    at /var/run/sidecar-identity/identity.json (task #29). Sidecar and agent
    start in parallel, so we poll briefly for that file to appear.

    No-op (so local dev / --mock / direct-to-Anthropic are unaffected) when
    ANTHROPIC_BASE_URL is unset, when an operator already supplied
    ANTHROPIC_CUSTOM_HEADERS, or when the identity file never appears (logged,
    then calls 401 visibly rather than silently bypassing governance)."""
    if not os.environ.get("ANTHROPIC_BASE_URL"):
        return
    if os.environ.get("ANTHROPIC_CUSTOM_HEADERS"):
        return  # operator-supplied headers win; don't clobber

    path = "/var/run/sidecar-identity/identity.json"
    token = ""
    for _ in range(max(1, wait_seconds)):
        try:
            with open(path) as f:
                token = (json.load(f) or {}).get("token", "") or ""
        except (OSError, json.JSONDecodeError):
            token = ""
        if token:
            break
        time.sleep(1)

    if not token:
        events.emit(
            "llm.proxy_auth.unavailable",
            path=path,
            reason="no gateway token after wait; proxy calls will 401",
        )
        return

    target = os.environ.get("ANTHROPIC_PROXY_TARGET_URL", "https://api.anthropic.com")
    os.environ["ANTHROPIC_CUSTOM_HEADERS"] = (
        f"X-DC-Auth: Bearer {token}\n"
        f"X-DC-Target-URL: {target}"
    )
    events.emit("llm.proxy_auth.ready", target=target, token_chars=len(token))


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

    # Task #55: if routed through the DefenseClaw guardrail proxy, materialize
    # the X-DC-Auth / X-DC-Target-URL headers before the LLM client is built.
    # Heartbeat is already fresh above, so the brief wait-for-identity here
    # cannot trip the liveness probe.
    _bootstrap_defenseclaw_proxy_headers()

    # Opt-in HTTP state server for the triage_mcp companion service.
    # Disabled by default (port=0) so legacy deployments without the MCP
    # are unaffected. Set AGENT_STATE_PORT=8080 (or any free port) to enable.
    state_runner = None
    state_port = int(os.environ.get("AGENT_STATE_PORT", "0"))
    if state_port > 0:
        try:
            state_runner = await _start_state_server(state, state_port)
        except Exception as exc:
            log.exception("failed to start state HTTP server on port %d", state_port)
            events.emit("agent.state_server.failed",
                        port=state_port, error=type(exc).__name__, message=str(exc)[:200])

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

    async with AsyncExitStack() as stack:
        splunk = await stack.enter_async_context(splunk_cm)

        # Task #56 stage 1: optional second MCP client → triage-mcp's
        # get_alert_history, so the agent can read its OWN past outcomes (and
        # rehydrate after a restart). Direct connection to triage-mcp:8081,
        # inspected at the agent boundary (mcp_inspect). Fail-open: any setup
        # error leaves the agent running without history rather than crash-looping.
        if cfg.history_enabled and not mock:
            if not cfg.history_mcp_command:
                events.emit("history.disabled", reason="HISTORY_MCP_COMMAND unset")
            else:
                try:
                    history_cm = SplunkClient(
                        cfg.history_mcp_command, cfg.history_mcp_args,
                        cfg.history_mcp_tool, cfg.splunk_row_limit,
                        env=cfg.history_mcp_env,
                    )
                    history = await stack.enter_async_context(history_cm)
                    await _rehydrate_history(history, cfg, state)
                except Exception as exc:
                    events.emit("history.init_failed",
                                error=type(exc).__name__, message=str(exc)[:200])

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

    if state_runner is not None:
        try:
            await state_runner.cleanup()
        except Exception:
            log.exception("error stopping state HTTP server")

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
        # Same proxy-auth bootstrap as run(), but with a short wait so a
        # preflight against a missing sidecar fails fast instead of hanging.
        _bootstrap_defenseclaw_proxy_headers(wait_seconds=5)
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

    # --- 4. Alert-history MCP (task #56) — only when enabled.
    if cfg.history_enabled:
        print("[+] Alert-history MCP (task #56)")
        if not cfg.history_mcp_command:
            print("      ✗ HISTORY_ENABLED but HISTORY_MCP_COMMAND is unset")
            failures.append("history_unconfigured")
        else:
            try:
                # Inspect-hook dry run: prove the agent-side gate is reachable.
                verdict = await mcp_inspect.inspect_tool(
                    cfg.history_mcp_tool, {"hours": cfg.history_lookback_hours})
                print(f"      ✓ inspect hook → action={verdict.get('action')} "
                      f"mode={verdict.get('mode') or '-'}")
                async with SplunkClient(
                    cfg.history_mcp_command, cfg.history_mcp_args,
                    cfg.history_mcp_tool, cfg.splunk_row_limit,
                    env=cfg.history_mcp_env,
                ) as history:
                    tools_result = await history._session.list_tools()
                    tool_names = [t.name for t in tools_result.tools]
                    if cfg.history_mcp_tool not in tool_names:
                        print(f"      ✗ '{cfg.history_mcp_tool}' NOT exposed by triage-mcp")
                        print(f"        available: {', '.join(tool_names)}")
                        failures.append("history_tool_missing")
                    else:
                        print(f"      ✓ '{cfg.history_mcp_tool}' is exposed")
                        payload = await history.call_tool({"hours": cfg.history_lookback_hours})
                        if isinstance(payload, dict) and payload.get("error"):
                            print(f"      ✗ tool returned error: {payload.get('error')}")
                            failures.append("history_query_error")
                        else:
                            n = len(payload.get("events", [])) if isinstance(payload, dict) else 0
                            print(f"      ✓ get_alert_history returned {n} event(s) "
                                  f"over {cfg.history_lookback_hours}h")
            except Exception as e:
                print(f"      ✗ {type(e).__name__}: {e}")
                failures.append("history")
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
