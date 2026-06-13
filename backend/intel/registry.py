"""Module capability registry — the analyst's model of its own tools.

The autonomous agent cannot plan if it does not know what each tool costs and
what each tool is good for. This registry encodes that meta-knowledge so the
planner can do value-of-information reasoning instead of running a fixed
pipeline. Cost is an abstract budget unit (rate-limit / latency proxy), not
seconds.
"""
from __future__ import annotations

import importlib

# Abstract collection cost. rep is expensive (HackerTarget 5/day), crt/otx
# moderate (heavier endpoints / rate limits), dns/whois/geo/email cheap.
MODULE_COST: dict[str, float] = {
    "whois": 1.0, "dns": 1.0, "geo": 1.0, "email": 1.0,
    "crt": 2.0, "otx": 2.0, "rep": 3.0,
}

# What kind of evidence each module yields, for planner introspection / UI.
MODULE_YIELDS: dict[str, list[str]] = {
    "whois": ["registrar", "expiry", "registrar_lock"],
    "dns": ["a", "mx", "spf", "dmarc", "ns", "email_security"],
    "crt": ["subdomains", "ct_presence", "staging_surface"],
    "geo": ["asn", "hosting", "proxy", "ownership"],
    "otx": ["threat_pulses", "malware_families", "reputation"],
    "rep": ["open_ports", "hosts", "exploitable_services"],
    "email": ["mx_validation", "permutations", "breach_pivot"],
}

_MODULE_MAP = {
    name: f"backend.modules.{name}_module"
    for name in ("email", "whois", "dns", "crt", "geo", "otx", "rep")
}


async def default_runner(name: str, target: str, client) -> dict:
    """Production runner: import and invoke the real recon module."""
    mod = importlib.import_module(_MODULE_MAP[name])
    return await mod.run(target, client)
