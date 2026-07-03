"""Shadow A/B harness (#73 quality gate). Runs every fixture through BOTH models —
Haiku via the anthropic provider and the vLLM model via the openai provider — and
compares their detection + triage decisions.

Haiku is the REFERENCE (the trusted production model): we measure how closely the
self-hosted model matches it. The primary gate is MISSED-P1 (Haiku says P1, the
vLLM model says lower / no_alert) — a missed P1 is the whole risk of a cheaper model.
There is no absolute ground truth here; treat every divergence (and every missed-P1)
as something a human should adjudicate. The fixtures' `reference` field is the
author's expected answer, shown alongside for that adjudication.

Run on a host that reaches BOTH Anthropic and the vLLM box (e.g. linda). From the
agent root, with ab_harness/ present:

  ANTHROPIC_API_KEY=sk-ant-... \
  LLM_BASE_URL=http://<box-priv-ip>:8000/v1 \
  VLLM_MODEL=stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ \
  HAIKU_MODEL=claude-haiku-4-5 \
  SOUL_PATH=SOUL.md \
  .venv/bin/python ab_harness/run_ab.py

Note: temperature is 0 on the vLLM side; the Anthropic side uses Claude defaults
(forced tool_choice keeps it fairly stable). Single run per fixture — for a rigorous
gate, run a few times and watch for variance, and expand the corpus (make_fixtures.py).
"""
import asyncio
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import events  # noqa: E402

# Capture per-model token usage by intercepting the usage events (and keep the
# harness output clean by not echoing the JSONL). Attribute lookup at call time,
# so patching events.emit after import is picked up by llm_client.
_USAGE: dict[str, dict] = {}
_orig_emit = events.emit


def _capture_emit(name: str, **kw):
    if name in ("llm.detection_pass", "llm.triage_pass"):
        mdl = kw.get("model", "?")
        u = _USAGE.setdefault(mdl, {"in": 0, "out": 0, "calls": 0})
        u["in"] += kw.get("input_tokens", 0) or 0
        u["out"] += kw.get("output_tokens", 0) or 0
        u["calls"] += 1
    # swallow — don't spam the harness output with per-call JSONL


events.emit = _capture_emit

from llm_client import LLMClient  # noqa: E402  (after patch so it binds events.emit lazily)

FIX = Path(__file__).resolve().parent / "fixtures"

# Haiku 4.5 list price ($/1M) for the cost column; vLLM is flat-rate (see #73), so we
# report its tokens but not a per-token price.
HAIKU_IN, HAIKU_OUT = 1.00, 5.00


def _sev_tier(s):
    return {"P1 CRITICAL": 3, "P2 HIGH": 2, "P3 MEDIUM": 1, "RESOLVED": 0}.get(s, -1)


def _load_fixtures():
    return [json.loads(p.read_text()) for p in sorted(FIX.glob("*.json"))]


async def _run(llm, fx):
    det = await llm.detection_pass(scan_data=fx["scan_data"],
                                   previous_alerts=fx["previous_alerts"])
    reports = {}
    if fx.get("drill_data"):
        tri = await llm.triage_pass(scan_data=fx["scan_data"], drill_data=fx["drill_data"],
                                    previous_alerts=fx["previous_alerts"])
        reports = {r.get("store"): r for r in tri.reports}
    return {"detect": {s.get("store") for s in det.correlate_stores}, "reports": reports}


async def main():
    soul = os.environ.get("SOUL_PATH", "SOUL.md")
    haiku = LLMClient(model=os.environ.get("HAIKU_MODEL", "claude-haiku-4-5"), soul_path=soul,
                      provider="anthropic", api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
    qwen = LLMClient(model=os.environ.get("VLLM_MODEL", "stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ"),
                     soul_path=soul, provider="openai",
                     base_url=os.environ["LLM_BASE_URL"],
                     vllm_api_key=os.environ.get("LLM_API_KEY", "EMPTY"))

    fixtures = _load_fixtures()
    a = {"det_match": 0, "det_missed": 0, "det_extra": 0, "sev_exact": 0, "sev_adj": 0,
         "sev_tot": 0, "dedup_match": 0, "dedup_tot": 0, "rc_match": 0, "rc_tot": 0,
         "missed_p1": [], "errors": 0}

    for fx in fixtures:
        try:
            h = await _run(haiku, fx)
            q = await _run(qwen, fx)
        except Exception as e:
            a["errors"] += 1
            print(f"\n[{fx['id']}] ERROR: {type(e).__name__}: {str(e)[:200]}")
            continue

        missed = h["detect"] - q["detect"]
        extra = q["detect"] - h["detect"]
        a["det_missed"] += len(missed)
        a["det_extra"] += len(extra)
        if h["detect"] == q["detect"]:
            a["det_match"] += 1
        det_line = ("match " + (str(sorted(h["detect"])) if h["detect"] else "(silent)")
                    if h["detect"] == q["detect"]
                    else f"DIVERGE  H={sorted(h['detect'])}  Q={sorted(q['detect'])}")
        print(f"\n[{fx['id']}] {fx['fault_type']}")
        print(f"  detection : {det_line}")

        for st in sorted(set(h["reports"]) | set(q["reports"])):
            rh, rq = h["reports"].get(st, {}), q["reports"].get(st, {})
            sh, sq = rh.get("severity"), rq.get("severity")
            dh, dq = rh.get("dedup_decision"), rq.get("dedup_decision")
            ch, cq = rh.get("root_cause_key"), rq.get("root_cause_key")
            a["sev_tot"] += 1
            a["sev_exact"] += (sh == sq)
            a["sev_adj"] += (abs(_sev_tier(sh) - _sev_tier(sq)) <= 1)
            a["dedup_tot"] += 1
            a["dedup_match"] += (dh == dq)
            a["rc_tot"] += 1
            a["rc_match"] += (ch == cq)
            if str(sh).startswith("P1") and not str(sq).startswith("P1"):
                a["missed_p1"].append((fx["id"], st, sh, sq, rq.get("action")))
            flag = "  <-- DIVERGE" if (sh != sq or dh != dq or ch != cq) else ""
            print(f"  triage {st}: sev H={sh}/Q={sq}  dedup H={dh}/Q={dq}  rc H={ch}/Q={cq}{flag}")
        ref = fx.get("reference", {})
        if ref:
            print(f"  reference : {ref}")

    n = len(fixtures)
    print("\n" + "=" * 64)
    print("AGGREGATE  (Haiku = reference; higher = closer match)")
    print(f"  fixtures run           : {n - a['errors']}/{n}" + (f"  ({a['errors']} errored)" if a["errors"] else ""))
    print(f"  detection exact-match  : {a['det_match']}/{n - a['errors']}")
    print(f"  detection MISSED       : {a['det_missed']}   (Haiku flagged, Qwen didn't — dangerous)")
    print(f"  detection over-flag    : {a['det_extra']}   (Qwen flagged, Haiku didn't — noisy)")
    if a["sev_tot"]:
        print(f"  severity exact         : {a['sev_exact']}/{a['sev_tot']}")
        print(f"  severity within-1-tier : {a['sev_adj']}/{a['sev_tot']}")
        print(f"  dedup agreement        : {a['dedup_match']}/{a['dedup_tot']}")
        print(f"  root-cause agreement   : {a['rc_match']}/{a['rc_tot']}")
    print(f"\n  *** MISSED-P1 (the gate): {len(a['missed_p1'])} ***")
    for mp in a["missed_p1"]:
        print(f"      {mp[0]} store {mp[1]}: Haiku={mp[2]}  Qwen={mp[3]}  action={mp[4]}")

    print("\n  cost / tokens this run:")
    for mdl, u in _USAGE.items():
        line = f"      {mdl}: {u['calls']} calls, in={u['in']} out={u['out']}"
        if mdl.startswith("claude"):
            usd = u["in"] / 1e6 * HAIKU_IN + u["out"] / 1e6 * HAIKU_OUT
            line += f"  ~${usd:.4f} (API list price)"
        else:
            line += "  (self-hosted — flat-rate, see #73; tokens shown for reference)"
        print(line)


if __name__ == "__main__":
    asyncio.run(main())
