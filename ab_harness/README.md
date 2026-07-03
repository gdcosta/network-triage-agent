# Shadow A/B harness (#73 quality gate)

Offline replay comparison of the **self-hosted vLLM model vs Haiku** on the agent's
real detection + triage decisions. Answers the #73 go/no-go: *can the 4-bit model
replace Haiku without missing P1s?*

**Haiku is the reference** (the trusted production model). We measure how closely the
vLLM model matches it. The primary gate is **MISSED-P1** — Haiku says P1, the vLLM
model says lower / no_alert. There is **no absolute ground truth**: every divergence,
and every missed-P1, should be adjudicated by a human. Each fixture's `reference`
field is the author's expected answer, printed to aid that judgment.

## Files
- `fixtures/*.json` — incident inputs, each `{scan_data, drill_data, previous_alerts, reference}`
  in the exact shape the agent consumes (`scan_data` = 4 scan results; `drill_data` =
  `{store: {drill_sdwan, drill_te, drill_meraki, drill_ise, correlate_timeline}}`).
- `make_fixtures.py` — regenerates the seed fixtures from `mock_splunk.py`'s canned shapes.
- `run_ab.py` — the harness: runs both models on every fixture, compares, reports.

## Run it (on a host that reaches BOTH Anthropic and the vLLM box — e.g. linda)

From the **agent root** (so `import llm_client` resolves):
```bash
ANTHROPIC_API_KEY=sk-ant-... \
LLM_BASE_URL=http://<box-priv-ip>:8000/v1 \
VLLM_MODEL=stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ \
HAIKU_MODEL=claude-haiku-4-5 \
SOUL_PATH=SOUL.md \
.venv/bin/python ab_harness/run_ab.py
```
Needs the same `.venv` (anthropic + httpx). The vLLM side goes **direct** to the box
(not through the DefenseClaw proxy — fine for an offline test). `LLM_MAX_TOKENS`
defaults to 4096 (fits the L4's 16384 window).

## Reading the output
Per fixture: detection match/diverge, then per-store triage severity/dedup/root-cause
(Haiku vs Qwen, `<-- DIVERGE` on any mismatch). Then the aggregate:
- **detection MISSED** — stores Haiku flagged that Qwen didn't (dangerous)
- **severity exact / within-1-tier**, **dedup agreement**, **root-cause agreement**
- **MISSED-P1** — the gate, listed case by case
- **cost / tokens** — real per-model token totals; Haiku priced at API list, vLLM is
  flat-rate (see #73)

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
