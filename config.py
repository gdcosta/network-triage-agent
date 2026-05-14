from __future__ import annotations

import json
import logging
import os
import shlex
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Config:
    # LLM (the brain)
    anthropic_api_key: str
    llm_model: str
    soul_path: str

    # Splunk MCP (data plane)
    splunk_mcp_command: str
    splunk_mcp_args: list[str]
    splunk_mcp_env: dict[str, str]
    splunk_tool_name: str
    splunk_row_limit: int

    # Teams (notification plane)
    teams_webhook_url: str

    # Polling
    poll_interval_seconds: int
    earliest_time: str
    latest_time: str

    # Liveness: the poll loop touches this file each cycle; a k8s exec
    # probe checks its age to confirm the loop is still turning.
    heartbeat_file: str

    # Card deep-link bases
    splunk_base_url: str
    meraki_base_url: str

    # Fleet roster: store_id -> display name (e.g. "Store 047 - Portland, OR")
    store_names: dict[str, str]


def _parse_env_pairs(s: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in s.split(","):
        pair = pair.strip()
        if not pair or "=" not in pair:
            continue
        k, v = pair.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def _load_store_registry(path: str) -> dict[str, str]:
    """Load the fleet roster JSON. Tolerant of a missing file — returns
    an empty dict so unfamiliar stores fall back to LLM-derived names."""
    p = Path(path)
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("could not load store_registry from %s: %s", path, e)
        return {}
    if not isinstance(raw, dict):
        return {}
    # Drop the optional _comment key + ignore non-string values.
    return {
        str(k): str(v) for k, v in raw.items()
        if not k.startswith("_") and isinstance(v, str)
    }


def load_config(mock: bool = False) -> Config:
    load_dotenv()

    api_key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not api_key and not mock:
        raise RuntimeError("ANTHROPIC_API_KEY is required (or pass --mock)")

    webhook = os.environ.get("TEAMS_WEBHOOK_URL", "").strip()
    if not webhook and not mock:
        raise RuntimeError("TEAMS_WEBHOOK_URL is required (or pass --mock)")

    cmd = os.environ.get("SPLUNK_MCP_COMMAND", "").strip()
    if not cmd and not mock:
        raise RuntimeError("SPLUNK_MCP_COMMAND is required (or pass --mock)")

    return Config(
        anthropic_api_key=api_key or "mock",
        llm_model=os.environ.get("LLM_MODEL", "claude-sonnet-4-6"),
        soul_path=os.environ.get("SOUL_PATH", "SOUL.md"),
        splunk_mcp_command=cmd or "mock",
        splunk_mcp_args=shlex.split(os.environ.get("SPLUNK_MCP_ARGS", "")),
        splunk_mcp_env=_parse_env_pairs(os.environ.get("SPLUNK_MCP_ENV", "")),
        splunk_tool_name=os.environ.get("SPLUNK_TOOL_NAME", "splunk_run_query"),
        splunk_row_limit=int(os.environ.get("SPLUNK_ROW_LIMIT", "1000")),
        teams_webhook_url=webhook or "mock://stdout",
        poll_interval_seconds=int(os.environ.get("POLL_INTERVAL_SECONDS", "30")),
        earliest_time=os.environ.get("EARLIEST_TIME", "-5m"),
        latest_time=os.environ.get("LATEST_TIME", "now"),
        heartbeat_file=os.environ.get("HEARTBEAT_FILE", "/tmp/agent-heartbeat"),
        splunk_base_url=os.environ.get("SPLUNK_BASE_URL", "https://splunk.example.com"),
        meraki_base_url=os.environ.get("MERAKI_BASE_URL", "https://dashboard.meraki.com"),
        store_names=_load_store_registry(
            os.environ.get("STORE_REGISTRY_PATH", "store_registry.json")
        ),
    )
