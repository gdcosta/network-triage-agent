# Triage agent image: Python runtime + Node (for the `mcp-remote` Splunk bridge).
# The agent shells out to `npx mcp-remote ...` to reach the Splunk MCP server,
# so the image needs Node. mcp-remote is baked in at build time so a pod start
# never depends on an npm registry fetch.
FROM node:22-bookworm-slim

# Python + the mcp-remote stdio bridge. Pinned for reproducible builds.
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-pip \
 && npm install -g mcp-remote@0.1.37 \
 && npm cache clean --force \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Dependencies first for layer caching — they change far less than the code.
COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# Application code. SOUL.md / store_registry.json are intentionally NOT copied —
# they are customer-specific and mount from a ConfigMap at runtime (see k8s/).
COPY *.py ./

# Run unprivileged.
RUN useradd --create-home --uid 10001 agent \
 && chown -R agent:agent /app
USER agent

# Unbuffered so the JSONL event stream flushes promptly to the OTel collector.
ENV PYTHONUNBUFFERED=1

# No args -> the polling loop. `--check` / `--mock` available for debugging.
ENTRYPOINT ["python3", "main.py"]
