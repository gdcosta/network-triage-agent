# Kubernetes deployment

Deploys the triage agent into the `net-triage-agent` namespace as a
single-replica background worker.

## How it fits the cluster

- **Logs:** the agent emits JSONL on stdout. The cluster's Splunk OTel
  Collector **agent DaemonSet** scrapes every container's stdout from
  `/var/log/pods/` and forwards it. Nothing to wire up — just deploy and
  the event stream flows to Splunk.
- **Singleton:** the agent polls Splunk and posts Teams cards on a fixed
  cadence. Two replicas would double every alert, so `replicas: 1` and
  `strategy: Recreate` (never two pods at once, even mid-rollout).
- **No Service / Gateway:** it serves no traffic. Liveness is an `exec`
  probe checking the freshness of a heartbeat file the poll loop touches
  each cycle — not an HTTP endpoint.
- **Image carries no customer data:** `SOUL.md` and `store_registry.json`
  come from a ConfigMap; credentials from a Secret. The image is just code.

## Prerequisites

- Namespace `net-triage-agent` (already exists in the cluster)
- The `localhost:5000` registry the cluster pulls from (same one
  `kl-scenario-controller` uses)
- Local files present in the repo root: `SOUL.md`, `store_registry.json`,
  and a `.env` with the real credential values

## 1. Build and push the image

```bash
# from the repo root
docker build -t localhost:5000/kl-triage-agent:latest .
docker push localhost:5000/kl-triage-agent:latest
```

Same registry flow used for `kl-scenario-controller`. The build needs no
secrets — `.dockerignore` keeps `.env`, `SOUL.md`, and `store_registry.json`
out of the build context.

## 2. Create the ConfigMap (SOUL.md + store_registry.json)

```bash
kubectl create configmap kl-triage-config \
  --namespace net-triage-agent \
  --from-file=SOUL.md \
  --from-file=store_registry.json
```

## 3. Create the Secret (credentials + Splunk MCP connection)

See `k8s/secret.example.yaml` for both options. The quick path —
imperatively, straight from your `.env` values:

```bash
kubectl create secret generic kl-triage-secrets \
  --namespace net-triage-agent \
  --from-literal=ANTHROPIC_API_KEY='sk-ant-...' \
  --from-literal=TEAMS_WEBHOOK_URL='https://...' \
  --from-literal=SPLUNK_MCP_COMMAND='npx' \
  --from-literal=SPLUNK_MCP_ARGS='-y mcp-remote https://splunk-mcp.example.com:8089/services/mcp --header "Authorization: Bearer <token>"' \
  --from-literal=SPLUNK_MCP_ENV='NODE_TLS_REJECT_UNAUTHORIZED=0'
```

The `SPLUNK_MCP_*` values are the same strings as your local `.env` — the
image bakes in `mcp-remote`, so `npx -y mcp-remote ...` resolves the global
install with no registry fetch at pod start.

## 4. Apply the Deployment

```bash
kubectl apply -f k8s/deployment.yaml
```

## 5. Verify

```bash
kubectl get pods -n net-triage-agent -l app=kl-triage-agent
kubectl logs  -n net-triage-agent -l app=kl-triage-agent --tail=50 -f
```

A healthy start emits `agent.start`, then `poll.start` / `scan.complete` /
`poll.complete` every `POLL_INTERVAL_SECONDS`. If the pod `CrashLoopBackOff`s,
check the logs — most likely a missing Secret key or the Splunk MCP endpoint
not being reachable from inside the cluster.

## Redeploying

After a **code change** — rebuild, push, restart (`imagePullPolicy: Always`
pulls the new `:latest`):

```bash
docker build -t localhost:5000/kl-triage-agent:latest . && docker push localhost:5000/kl-triage-agent:latest
kubectl rollout restart deployment/kl-triage-agent -n net-triage-agent
```

After a **SOUL.md or store_registry.json change** — refresh the ConfigMap,
then restart:

```bash
kubectl create configmap kl-triage-config -n net-triage-agent \
  --from-file=SOUL.md --from-file=store_registry.json \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl rollout restart deployment/kl-triage-agent -n net-triage-agent
```

After a **credential change** — recreate the Secret the same way, then
`rollout restart`.

## Live LLM provider toggle + vLLM governance (task #1)

**How it's wired.** The agent holds an Anthropic client **and** a vLLM client at
once and picks the active one **each poll cycle**. On the vLLM path it posts plain
OpenAI to the **LLM guardrail shim** in the DefenseClaw sidecar (loopback
`127.0.0.1:4100`) — *not* the box directly. The shim inspects the prompt via
DefenseClaw's `/api/v1/inspect/request` (emitting the audit trail) and forwards to
the box **holding the vLLM token**. So the agent holds no token and the *sidecar*
egresses to the box. (DefenseClaw's own `:4000` proxy can't route to a custom vLLM
host, which is why this first-party shim exists — see `kl-governance/llm_shim.py`.)

**Three ConfigMap keys drive it, all live (no pod restart):**

| Key (`kl-triage-config`) | Read by | Values | Meaning |
|---|---|---|---|
| `llm_provider` | agent | `anthropic` \| `openai` | which backend is live |
| `vllm_model`   | agent | e.g. `Qwen/Qwen3-30B-A3B-Instruct-2507-FP8` | request-body model id |
| `vllm_target`  | **shim** | `http://<box-ip>:8000/v1` | the box (follows a relaunch) |

The agent's own endpoint (`LLM_BASE_URL` → the shim loopback) is **static**; the
changing box IP lives in `vllm_target`, which the shim re-reads each request — so
a relaunched box is a ConfigMap patch, no restart. Absent keys → env defaults
(`LLM_PROVIDER` defaults to `anthropic`).

**Flip to the vLLM box** (patch merge — touches only these keys, leaves SOUL.md /
store_registry.json intact, no rollout):

```bash
kubectl -n net-triage-agent patch configmap kl-triage-config --type merge -p \
  '{"data":{"llm_provider":"openai","vllm_model":"Qwen/Qwen3-30B-A3B-Instruct-2507-FP8","vllm_target":"http://172.31.15.118:8000/v1"}}'
```

**Point at a relaunched box (new IP) — shim only, no restart:**

```bash
kubectl -n net-triage-agent patch configmap kl-triage-config --type merge -p \
  '{"data":{"vllm_target":"http://<new-box-ip>:8000/v1"}}'
```

**Flip back to Anthropic** (instant — that client is always built):

```bash
kubectl -n net-triage-agent patch configmap kl-triage-config --type merge -p \
  '{"data":{"llm_provider":"anthropic"}}'
```

> If you tested an earlier build, **delete the stale `llm_base_url` key** —
> it's no longer used (the box URL moved to `vllm_target`):
> `kubectl -n net-triage-agent patch configmap kl-triage-config --type json -p '[{"op":"remove","path":"/data/llm_base_url"}]'`

ConfigMap-volume propagation takes up to ~60s; the loop then emits `llm.mode`
(`mode:"openai"`), and a bad/missing `vllm_model` fails **safe** (`llm.mode_fallback`
→ stays on Anthropic).

**Egress + proof.** The *sidecar* forwards to the box, so its Cilium egress must
allow `<box-ip>:8000` (uncomment the vLLM rule in `k8s/cilium-egress-policy.yaml`,
set the IP, apply). The box SG must allow inbound `:8000` from the cluster node IP.
Governance proof: an `inspect-request-*` event under `sourcetype=defenseclaw:inspect`
in linda's `defenseclaw_audit` index for each vLLM call (plus `shim.inspect` /
`shim.forward` JSONL from the sidecar).

## Tuning

- **Resources** (`deployment.yaml`): requests 100m / 192Mi, limits
  500m / 512Mi. The agent is mostly idle between 30s polls; bumps come
  from the Node `mcp-remote` subprocess and the LLM/Splunk round trips.
- **Liveness probe**: `< 150s` heartbeat age, `failureThreshold: 3`,
  `periodSeconds: 30` — roughly 4 minutes of a hung poll loop before a
  restart. Tighten if you want faster recovery.
- **Splunk index routing**: the Splunk OTel Collector honours pod
  annotations like `splunk.com/index`. Add one to `deployment.yaml`'s pod
  template if these logs should land in a dedicated index.
