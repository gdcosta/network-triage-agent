"""Shadow A/B harness (#73 quality gate). Runs every fixture through BOTH models —
Haiku (anthropic provider) and the vLLM model (openai provider) — and scores each
against the fixture's adjudicated `reference` (the intended answer), NOT against the
other model. Both sides run at temperature=0 for determinism; --runs N repeats each
fixture to surface any residual non-determinism.

Why reference-based + deterministic: an earlier version compared Qwen-vs-Haiku on a
single run, but Haiku (Claude defaults) flip-flopped P1/P2 on borderline cases across
runs — so "missed-P1 vs Haiku" produced false alarms. The reference is the yardstick;
the primary gate is REFERENCE missed-P1 (reference=P1 but a model says lower). There
is still no absolute truth — the `reference` is the fixture author's adjudication, so
keep it honest and revisit divergences.

Run on a host that reaches BOTH Anthropic and the vLLM box (e.g. linda), from the
agent root:

  read -rs ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY ; unset ANTHROPIC_BASE_URL
  LLM_BASE_URL=http://<box-priv-ip>:8000/v1 \
  VLLM_MODEL=stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ HAIKU_MODEL=claude-haiku-4-5 \
  SOUL_PATH=SOUL.md .venv/bin/python ab_harness/run_ab.py --runs 3
"""
import argparse
import asyncio
import json
import os
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import events  # noqa: E402

# Capture per-model token usage by intercepting usage events (keep output clean).
_USAGE: dict[str, dict] = {}


def _capture_emit(name: str, **kw):
    if name in ("llm.detection_pass", "llm.triage_pass"):
        u = _USAGE.setdefault(kw.get("model", "?"), {"in": 0, "out": 0, "calls": 0})
        u["in"] += kw.get("input_tokens", 0) or 0
        u["out"] += kw.get("output_tokens", 0) or 0
        u["calls"] += 1


events.emit = _capture_emit

from llm_client import LLMClient  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
HAIKU_IN, HAIKU_OUT = 1.00, 5.00  # $/1M for the cost column


def _load_fixtures():
    return [json.loads(p.read_text()) for p in sorted(FIX.glob("*.json"))]


def _ref_report(reports: dict, ref: dict) -> dict:
    """The report for the reference's store (fixtures are single-store)."""
    stores = ref.get("detect_stores", [])
    return reports.get(stores[0], {}) if stores else {}


async def _run(llm, fx):
    det = await llm.detection_pass(scan_data=fx["scan_data"],
                                   previous_alerts=fx["previous_alerts"])
    reports = {}
    if fx.get("drill_data"):
        tri = await llm.triage_pass(scan_data=fx["scan_data"], drill_data=fx["drill_data"],
                                    previous_alerts=fx["previous_alerts"])
        reports = {r.get("store"): r for r in tri.reports}
    return {"detect": {s.get("store") for s in det.correlate_stores}, "reports": reports}


def _new_score():
    return {"det_ok": 0, "det_tot": 0, "sev_ok": 0, "sev_tot": 0,
            "dedup_ok": 0, "dedup_tot": 0, "rc_ok": 0, "rc_tot": 0,
            "missed_p1": [], "variance": []}


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=1, help="repeat each fixture N times")
    args = ap.parse_args()

    soul = os.environ.get("SOUL_PATH", "SOUL.md")
    models = [
        ("haiku", LLMClient(model=os.environ.get("HAIKU_MODEL", "claude-haiku-4-5"),
                            soul_path=soul, provider="anthropic",
                            api_key=os.environ.get("ANTHROPIC_API_KEY", ""), temperature=0)),
        ("qwen", LLMClient(model=os.environ.get("VLLM_MODEL", "stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ"),
                           soul_path=soul, provider="openai", base_url=os.environ["LLM_BASE_URL"],
                           vllm_api_key=os.environ.get("LLM_API_KEY", "EMPTY"), temperature=0)),
    ]
    score = {label: _new_score() for label, _ in models}
    fixtures = _load_fixtures()

    for fx in fixtures:
        ref = fx.get("reference", {})
        ref_sev = ref.get("severity")
        print(f"\n[{fx['id']}]  ref: detect={ref.get('detect_stores')} sev={ref_sev}"
              + (f" dedup={ref['dedup_decision']}" if ref.get("dedup_decision") else ""))
        for label, llm in models:
            sevs, dets, deds, rcs = [], [], [], []
            for _ in range(args.runs):
                try:
                    res = await _run(llm, fx)
                except Exception as e:
                    print(f"    {label:6}: ERROR {type(e).__name__}: {str(e)[:160]}")
                    continue
                s = score[label]
                # detection vs reference
                s["det_tot"] += 1
                det_ok = res["detect"] == set(ref.get("detect_stores", []))
                s["det_ok"] += det_ok
                dets.append("ok" if det_ok else f"{sorted(res['detect'])}")
                rep = _ref_report(res["reports"], ref)
                # severity vs reference
                if ref_sev is not None:
                    sev = rep.get("severity")
                    sevs.append(sev)
                    s["sev_tot"] += 1
                    s["sev_ok"] += (sev == ref_sev)
                    if str(ref_sev).startswith("P1") and not str(sev).startswith("P1"):
                        s["missed_p1"].append((fx["id"], sev))
                # dedup vs reference
                if ref.get("dedup_decision"):
                    dd = rep.get("dedup_decision")
                    deds.append(dd)
                    s["dedup_tot"] += 1
                    s["dedup_ok"] += (dd == ref["dedup_decision"])
                # root cause vs reference
                if ref.get("root_cause_key"):
                    rc = rep.get("root_cause_key")
                    rcs.append(rc)
                    s["rc_tot"] += 1
                    s["rc_ok"] += (rc == ref["root_cause_key"])
            # per-fixture per-model line
            if ref_sev is not None and sevs:
                dist = Counter(sevs)
                distr = " ".join(f"{k}×{v}" for k, v in dist.items())
                tag = "OK" if all(s0 == ref_sev for s0 in sevs) else "MISS-vs-ref"
                var = ""
                if len(dist) > 1:
                    var = "  <VARIANCE>"
                    score[label]["variance"].append(fx["id"])
                extra = f"  dedup={Counter(deds)}" if deds else ""
                print(f"    {label:6}: sev {distr} (ref {ref_sev}) {tag}{extra}{var}")
            else:
                print(f"    {label:6}: detect {Counter(dets)}")

    # ---- aggregate ----
    print("\n" + "=" * 66)
    print(f"PER-MODEL ACCURACY vs adjudicated reference  ({args.runs} run(s) x {len(fixtures)} fixtures)")
    for label, _ in models:
        s = score[label]
        print(f"\n  {label}:")
        print(f"    detection  : {s['det_ok']}/{s['det_tot']}")
        if s["sev_tot"]:
            print(f"    severity   : {s['sev_ok']}/{s['sev_tot']}   (exact match to reference)")
        if s["dedup_tot"]:
            print(f"    dedup      : {s['dedup_ok']}/{s['dedup_tot']}")
        if s["rc_tot"]:
            print(f"    root-cause : {s['rc_ok']}/{s['rc_tot']}")
        print(f"    *** MISSED-P1 vs reference: {len(s['missed_p1'])} ***"
              + (f"  {s['missed_p1']}" if s["missed_p1"] else "  (the gate)"))
        if s["variance"]:
            print(f"    NON-DETERMINISM: severity varied across runs on {sorted(set(s['variance']))}")

    print("\n  cost / tokens this run:")
    for mdl, u in _USAGE.items():
        line = f"    {mdl}: {u['calls']} calls, in={u['in']} out={u['out']}"
        if mdl.startswith("claude"):
            line += (f"  ~${u['in']/1e6*HAIKU_IN + u['out']/1e6*HAIKU_OUT:.4f} (API list;"
                     " NOTE excludes prompt-cached SOUL served as cache_read at 0.1x)")
        else:
            line += "  (self-hosted flat-rate, see #73)"
        print(line)


if __name__ == "__main__":
    asyncio.run(main())
