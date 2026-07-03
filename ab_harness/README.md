# Shadow A/B harness (#73 quality gate)

Offline replay comparison of the **self-hosted vLLM model vs Haiku** on the agent's
real detection + triage decisions. Answers the #73 go/no-go: *can the 4-bit model
replace Haiku without missing P1s?*

Each model is scored **against the fixture's adjudicated `reference`** (the intended
answer), NOT against the other model — because the reference model (Haiku, at Claude
defaults) flip-flops P1/P2 on borderline cases across runs, which made an earlier
"vs-Haiku" comparison produce false missed-P1s. Both sides run at **temperature=0**
for determinism, and **`--runs N`** repeats each fixture to surface residual
non-determinism. The primary gate is **MISSED-P1 vs reference** (reference=P1 but a
model says lower). The `reference` is still a human adjudication, not absolute truth —
keep it honest and revisit divergences.

## Files
- `fixtures/*.json` — incident inputs, each `{scan_data, drill_data, previous_alerts, reference}`
  in the exact shape the agent consumes (`scan_data` = 4 scan results; `drill_data` =
  `{store: {drill_sdwan, drill_te, drill_meraki, drill_ise, correlate_timeline}}`).
- `make_fixtures.py` — regenerates the seed fixtures from `mock_splunk.py`'s canned shapes.
- `run_ab.py` — the harness: runs both models on every fixture, compares, reports.

## Run it (on a host that reaches BOTH Anthropic and the vLLM box — e.g. linda)

From the **agent root** (so `import llm_client` resolves):
```bash
read -rs ANTHROPIC_API_KEY && export ANTHROPIC_API_KEY ; unset ANTHROPIC_BASE_URL
LLM_BASE_URL=http://<box-priv-ip>:8000/v1 \
VLLM_MODEL=stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ \
HAIKU_MODEL=claude-haiku-4-5 \
SOUL_PATH=SOUL.md \
.venv/bin/python ab_harness/run_ab.py --runs 3
```
`read -rs` keeps the key out of shell history; **`unset ANTHROPIC_BASE_URL`** so Haiku
goes direct to Anthropic (not a DefenseClaw proxy that isn't running here). Needs the
same `.venv` (anthropic + httpx). The vLLM side goes **direct** to the box. `--runs N`
repeats each fixture (default 1). `LLM_MAX_TOKENS` defaults to 4096 (fits the L4's
16384 window).

## Reading the output
Per fixture, per model: the severity distribution across runs (e.g. `P2 HIGH×3` or
`P2 HIGH×2 P1 CRITICAL×1 <VARIANCE>`) vs the `reference`, tagged `OK` / `MISS-vs-ref`.
Then per-model aggregate **vs the reference**:
- **detection** — model's flagged stores == reference's
- **severity** — exact match to reference severity
- **dedup**, **root-cause** — vs reference
- **MISSED-P1 vs reference** — the gate, listed case by case
- **NON-DETERMINISM** — fixtures where a model's severity varied across runs (with
  temperature=0 this should be empty; if not, that model is unstable on that case)
- **cost / tokens** — per-model totals; Haiku priced at API list (note: excludes the
  prompt-cached SOUL, served as `cache_read` at 0.1x), vLLM is flat-rate (see #73)

## Corpus
Seed set covers the WAN faults `mock_splunk.py` scripts (healthy, WAN-down P1,
WAN+TE cascade, WAN dedup-skip). **Expand toward the full fault taxonomy** —
`ap_hardware_failure`, `ise_policy_rejection`, `camera_wifi_flap`, `switch_failure`,
`wan_degraded` (see `../../kl-scenario-controller/event-templates.json`) — by adding
shapes + fixtures in `make_fixtures.py`, or hand-authoring JSON in `fixtures/` to the
same schema. Also add **P2/P3 and false-positive** fixtures so severity discrimination
and over-alerting are measured, not just the easy P1.

## Caveats
- **Single run per fixture.** For a rigorous gate, run a few times and watch variance
  (vLLM is temp 0; Haiku uses Claude defaults with forced tool_choice — fairly stable).
- **Reference ≠ truth.** Haiku can be wrong too; adjudicate divergences.
- A bigger corpus is what turns "looks good" into a defensible gate.
