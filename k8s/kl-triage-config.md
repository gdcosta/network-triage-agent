# ConfigMap `kl-triage-config` (namespace `net-triage-agent`)

There is **no manifest** for this ConfigMap — it is created by hand with
`kubectl create configmap … --from-file` and then patched live. This page is
its documentation. (Key list verified against the live cluster 2026-11-12.)

> **WARNING — this ConfigMap is the ONLY deployed copy of the agent's SOUL.**
> `SOUL.md` (the agent's system prompt) and `store_registry.json` (the fleet
> roster) are **gitignored** — they never reach git, the image, or any release
> zip. The copy in this ConfigMap is what the running agent actually uses; the
> `SOUL.md` in your working tree can drift from it (it already has: the local
> file and the live key differ in size). Before editing or re-creating the
> ConfigMap, **dump the live one first** so you don't overwrite a newer SOUL
> with a stale local file:
>
> ```bash
> kubectl -n net-triage-agent get configmap kl-triage-config \
>   -o jsonpath='{.data.SOUL\.md}' > SOUL.live-$(date +%F).md   # gitignored copy; do NOT commit
> kubectl -n net-triage-agent get configmap kl-triage-config \
>   -o jsonpath='{.data.store_registry\.json}' > store_registry.live-$(date +%F).json
> ```
>
> Back those up somewhere outside git. Deleting or re-creating the ConfigMap
> from a stale local `SOUL.md` silently changes the agent's behaviour on the
> next volume sync (~60 s) with no git history to roll back to.

## Keys, and what reads them

The ConfigMap is mounted **as a whole volume** (no `items:` filter) read-only at
`/config`, so every key appears as a file `/config/<key>`.

| Key | Kind | Read by | How |
|---|---|---|---|
| `SOUL.md` | file | `kl-triage-agent` / `triage-agent` (`llm_client.py`) | `SOUL_PATH=/config/SOUL.md` — the LLM system prompt. Read at startup → **needs a pod restart** to take effect. |
| `store_registry.json` | file | `triage-agent` (`config.py` → `teams_card.py`) and `triage-mcp` (`triage_mcp.py`, city/timezone enrichment) | `STORE_REGISTRY_PATH=/config/store_registry.json` in both Deployments. `triage-mcp` mounts the same ConfigMap read-only (`k8s/triage-mcp.yaml`). Read at startup → restart. Optional: absent file only disables enrichment/friendly names. |
| `llm_provider` | scalar | `triage-agent` (`config.py: current_provider`) | `LLM_PROVIDER_FILE=/config/llm_provider` — `anthropic` \| `openai` \| `vllm`. Re-read **every poll cycle**; no restart. Absent/blank → env default (`LLM_PROVIDER`, default `anthropic`). |
| `vllm_model` | scalar | `triage-agent` (`config.py: current_vllm_model`) | `VLLM_MODEL_FILE=/config/vllm_model` — request-body model id for the self-hosted model (only used when provider is `vllm`). Re-read per cycle; bad/missing value fails safe (`llm.mode_fallback` → Anthropic). |
| `vllm_target` | scalar | `triage-agent` pod's **`defenseclaw-sidecar`** LLM shim (`kl-governance/llm_shim.py`) | `VLLM_TARGET_FILE=/config/vllm_target` — base URL (`…/v1`) of the self-hosted vLLM box. Re-read on every request, so a relaunched box (new IP) is a ConfigMap patch, no restart. The sidecar mounts this ConfigMap for this key only. |
| `reminder_interval_seconds` | scalar | `triage-agent` (`config.py: current_reminder_interval`) | `REMINDER_INTERVAL_FILE=/config/reminder_interval_seconds` — seconds between STILL-ACTIVE reminder cards; `0` disables. Re-read per cycle; absent/garbage → env `REMINDER_INTERVAL_SECONDS` → default 1800. |

Live values of the non-secret scalars (2026-11-12): `llm_provider` = `vllm`,
`vllm_model` = `Qwen/Qwen3-32B-FP8`, `reminder_interval_seconds` = `900`,
`vllm_target` = `http://<vllm-box-ip>:8000/v1` (value is an internal address —
not recorded here).

ConfigMap-volume propagation takes up to ~60 s (kubelet sync). Files-as-keys
(`SOUL.md`, `store_registry.json`) are only read at process start, hence the
restart; the scalar keys are polled and need none.

## Create / refresh recipe

Run from the repo root (where the gitignored `SOUL.md` and
`store_registry.json` live). `--dry-run=client -o yaml | kubectl apply -f -`
makes it idempotent (create **or** update in place):

```bash
kubectl create configmap kl-triage-config \
  --namespace net-triage-agent \
  --from-file=SOUL.md \
  --from-file=store_registry.json \
  --from-literal=llm_provider='vllm' \
  --from-literal=vllm_model='Qwen/Qwen3-32B-FP8' \
  --from-literal=vllm_target='http://<vllm-box-ip>:8000/v1' \
  --from-literal=reminder_interval_seconds='900' \
  --dry-run=client -o yaml | kubectl apply -f -

# SOUL.md / store_registry.json are read at startup:
kubectl rollout restart deployment/kl-triage-agent -n net-triage-agent
# triage-mcp reads store_registry.json at startup too, if that file changed:
kubectl rollout restart deployment/triage-mcp -n net-triage-agent
```

Notes on the recipe:

- Every `--from-literal` **overwrites** the live value with what you type. If you
  are only refreshing `SOUL.md`, **omit the scalar flags**: the live
  ConfigMap's `last-applied` annotation records only the two file keys, so the
  three-way `apply` leaves `llm_provider` / `vllm_model` / `vllm_target` /
  `reminder_interval_seconds` untouched. (This is also why the shorter
  two-`--from-file` recipe in `README.md` is safe for a SOUL refresh.)
- A **fresh** namespace needs the scalar keys only if you want non-default
  behaviour: with none of them present the agent runs on `anthropic` with an
  1800 s reminder interval.
- To change just a scalar live, prefer a merge patch (touches nothing else, no
  rollout):
  ```bash
  kubectl -n net-triage-agent patch configmap kl-triage-config --type merge \
    -p '{"data":{"reminder_interval_seconds":"900"}}'
  ```
- Never `kubectl delete configmap kl-triage-config` — both Deployments mount it
  as a required volume, so a restart of either pod would fail until it is
  re-created, and the only SOUL copy would be gone (see warning at top).

See also: the "Live LLM provider toggle" section of `k8s/README.md` for the
provider/box flip procedure.
