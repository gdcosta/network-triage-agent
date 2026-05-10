from __future__ import annotations

import re

# The 3-digit store number is the universal correlation key. It surfaces
# differently in each domain — these regexes pull it back out.
HOSTNAME_RE = re.compile(r"kl-(\d{1,3})-", re.IGNORECASE)
NETWORK_ID_RE = re.compile(r"N_KL0+(\d{1,3})$", re.IGNORECASE)
ISE_DEVICE_RE = re.compile(r"KL-(\d{1,3})-", re.IGNORECASE)
TE_AGENT_RE = re.compile(r"kl-te-[a-z]+-(\d{1,3})\.", re.IGNORECASE)


def _norm(n: str | None) -> str | None:
    if not n:
        return None
    return n.zfill(3)


def store_from_hostname(hostname: str | None) -> str | None:
    if not hostname:
        return None
    m = HOSTNAME_RE.search(hostname)
    return _norm(m.group(1)) if m else None


def store_from_network_id(network_id: str | None) -> str | None:
    if not network_id:
        return None
    m = NETWORK_ID_RE.search(network_id)
    return _norm(m.group(1)) if m else None


def store_from_ise_device(name: str | None) -> str | None:
    if not name:
        return None
    m = ISE_DEVICE_RE.search(name)
    return _norm(m.group(1)) if m else None


def store_from_te_agent(agent: str | None) -> str | None:
    if not agent:
        return None
    m = TE_AGENT_RE.search(agent)
    return _norm(m.group(1)) if m else None


def hostname_pattern(store: str) -> str:
    return f"kl-{store}-*"


def network_id_for(store: str) -> str:
    return f"N_KL0000{store}"


def ise_device_pattern(store: str) -> str:
    return f"KL-{store}-AP"
