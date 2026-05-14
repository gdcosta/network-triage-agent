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
