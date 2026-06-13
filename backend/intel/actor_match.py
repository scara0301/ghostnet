"""Threat-Actor Matching by behaviour, not signatures.

Signature matching ("this IP is on a blocklist") fails the moment an actor
rotates infrastructure. We instead fingerprint *how* infrastructure is built and
operated, then score behavioural similarity against known-actor profiles. An
actor who always uses bulletproof ASNs, freshly-registered domains, Let's
Encrypt certs and DGA-style hostnames looks the same even on brand-new IPs.

The target is reduced to a behavioural feature vector; each actor profile is a
weighted feature vector; the match score is weighted cosine similarity. Profiles
here are illustrative seeds -- in production they are mined from historical
campaign clusters (see architecture doc, "Actor Profile Mining").
"""
from __future__ import annotations

import math
import re

from backend.intel.graph import DigitalTwin
from backend.intel.schemas import ActorMatch

# Each profile: behavioural feature -> emphasis weight in [0,1].
ACTOR_PROFILES: dict[str, dict[str, float]] = {
    "FIN-PHISH-CLUSTER": {
        "fresh_domain": 0.9, "le_cert": 0.6, "dga_naming": 0.5,
        "cheap_registrar": 0.7, "single_ip_fanout": 0.4, "punycode": 0.6,
    },
    "BULLETPROOF-HOST-APT": {
        "bulletproof_asn": 0.9, "self_signed": 0.5, "port_sprawl": 0.7,
        "no_email_security": 0.6, "fast_flux": 0.8,
    },
    "COMMODITY-SCANNER": {
        "port_sprawl": 0.8, "no_tls": 0.6, "datacenter_asn": 0.7,
        "single_ip_fanout": 0.3,
    },
}

_DGA_RE = re.compile(r"[bcdfghjklmnpqrstvwxz]{5,}|[0-9]{4,}")
_BULLETPROOF_HINTS = ("bulletproof", "offshore", "anonymous", "hosting")


def fingerprint(twin: DigitalTwin) -> dict[str, float]:
    """Reduce the twin to behavioural features in [0,1]."""
    f: dict[str, float] = {}
    domains = twin.of_type("domain") + twin.of_type("subdomain")
    ips = twin.of_type("ip")
    asns = twin.of_type("asn")

    names = [n.id for n in domains]
    if names:
        dga = sum(1 for n in names if _DGA_RE.search(n.split(".")[0])) / len(names)
        f["dga_naming"] = round(dga, 3)
        f["punycode"] = round(sum(1 for n in names if n.startswith("xn--")) / len(names), 3)

    f["single_ip_fanout"] = 1.0 if (len(domains) >= 3 and len(ips) == 1) else 0.0
    f["fast_flux"] = 1.0 if (len(ips) >= 5 and len(domains) <= 2) else 0.0

    port_total = sum(len(n.attrs.get("open_ports", []) or []) for n in ips)
    f["port_sprawl"] = round(min(1.0, port_total / 12.0), 3)

    asn_labels = " ".join(n.label.lower() for n in asns)
    f["bulletproof_asn"] = 1.0 if any(h in asn_labels for h in _BULLETPROOF_HINTS) else 0.0
    f["datacenter_asn"] = 1.0 if any(k in asn_labels for k in ("ovh", "hetzner", "digitalocean", "vultr", "linode")) else 0.0

    certs = twin.of_type("cert")
    issuers = " ".join((c.attrs.get("issuer", "") or "").lower() for c in certs)
    f["le_cert"] = 1.0 if "let's encrypt" in issuers or "letsencrypt" in issuers else 0.0
    f["self_signed"] = 1.0 if "self" in issuers else 0.0

    for d in domains:
        if d.attrs.get("age_days") is not None and d.attrs["age_days"] < 90:
            f["fresh_domain"] = 1.0
    f.setdefault("fresh_domain", 0.0)
    f["no_tls"] = 1.0 if (certs == [] and domains) else 0.0
    f["no_email_security"] = 1.0 if not any(n.type == "mx" for n in twin.nodes.values()) else 0.0
    return f


def _cosine(a: dict[str, float], b: dict[str, float]) -> tuple[float, list[str]]:
    keys = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in keys)
    na = math.sqrt(sum(v * v for v in a.values())) or 1e-9
    nb = math.sqrt(sum(v * v for v in b.values())) or 1e-9
    matched = sorted([k for k in keys if a[k] > 0.3 and b[k] > 0.3],
                     key=lambda k: a[k] * b[k], reverse=True)
    return dot / (na * nb), matched


def match_actors(twin: DigitalTwin, min_score: float = 0.25) -> list[ActorMatch]:
    fp = fingerprint(twin)
    matches: list[ActorMatch] = []
    for actor, profile in ACTOR_PROFILES.items():
        score, feats = _cosine(fp, profile)
        if score >= min_score:
            matches.append(ActorMatch(
                actor=actor, score=round(score, 4), matched_features=feats,
                rationale="behavioural similarity on " + (", ".join(feats) or "weak signals"),
            ))
    matches.sort(key=lambda m: m.score, reverse=True)
    return matches
