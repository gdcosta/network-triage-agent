"""Throwaway smoke test for the vLLM (openai) LLM path — NOT committed/needed at runtime.

Hits the REAL vLLM endpoint with one detection_pass of sample data and prints the
schema-conforming result, latency, and token usage. Confirms Qwen3-AWQ actually
produces valid structured output through our prompts before wiring the full agent.

Prereqs (from the linda Mac):
  1. Tunnel the box to localhost:   ssh -L 8000:localhost:8000 vllm    (leave it open)
  2. In another shell, from the agent repo:
       LLM_PROVIDER=openai \
       LLM_BASE_URL=http://localhost:8000/v1 \
       LLM_MODEL=stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ \
       SOUL_PATH=SOUL.md \
       .venv/bin/python smoke_vllm.py
"""
import asyncio
import os
import time

from llm_client import LLMClient

SAMPLE_SCANS = {
    "sdwan": [{"store": "047", "site": "Portland", "tunnel_state": "down", "loss_pct": 100}],
    "te": [{"store": "047", "path_score": 12}],
    "meraki": [],
    "ise": [],
}


async def main() -> None:
    base = os.environ.get("LLM_BASE_URL")
    model = os.environ.get("LLM_MODEL", "stelterlab/Qwen3-30B-A3B-Instruct-2507-AWQ")
    soul = os.environ.get("SOUL_PATH", "SOUL.md")
    if not base:
        raise SystemExit("set LLM_BASE_URL (e.g. http://localhost:8000/v1)")

    c = LLMClient(model=model, soul_path=soul, provider="openai",
                  base_url=base, vllm_api_key=os.environ.get("LLM_API_KEY", "EMPTY"))

    t0 = time.monotonic()
    dec = await c.detection_pass(scan_data=SAMPLE_SCANS, previous_alerts={})
    dt = time.monotonic() - t0

    print(f"\n--- detection_pass returned in {dt:.1f}s ---")
    print("summary          :", dec.summary)
    print("correlate_stores :", dec.correlate_stores)
    print("recovery_stores  :", dec.recovery_stores)
    print("\n(schema conformance is enforced by vLLM guided decoding — if this printed, it worked)")


if __name__ == "__main__":
    asyncio.run(main())
