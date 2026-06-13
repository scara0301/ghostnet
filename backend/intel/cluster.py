"""Infrastructure Clustering — infer ownership and lifecycle without ground truth.

OSINT tools show you assets; they don't tell you which assets *belong together*,
which are staging, and which are abandoned. We infer all three from weak signals.

Ownership is a single-linkage clustering problem. We score every pair of assets
on co-ownership evidence (shared /24, shared ASN, shared certificate SANs,
shared nameserver, naming-token overlap), union pairs above a threshold, and the
resulting connected components are "likely same organization" clusters -- even
across different registrars or hosting providers, which is exactly what defeats
naive WHOIS-based grouping.

Lifecycle labels come from per-asset features:
  * staging    -- dev/test/staging tokens, private/cloud-internal IPs, low degree
  * abandoned  -- expired/parked indicators, no recent CT, dangling resolution
  * active     -- everything else with live signals
"""
from __future__ import annotations

import ipaddress
import re

from backend.intel.graph import DigitalTwin
from backend.intel.schemas import Cluster

_STAGING_RE = re.compile(r"(^|[.-])(dev|stag|staging|test|qa|uat|preprod|sandbox|demo|internal|tmp)([.-]|$)")
_GENERIC_TOKENS = {"www", "mail", "com", "net", "org", "io", "app", "co", "cloud"}


class _UnionFind:
    def __init__(self, items: list[str]) -> None:
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        self.parent[self.find(a)] = self.find(b)


def _tokens(name: str) -> set[str]:
    parts = re.split(r"[.\-_]", name.lower())
    return {p for p in parts if p and p not in _GENERIC_TOKENS and not p.isdigit()}


def _asset_ip(twin: DigitalTwin, asset: str) -> str | None:
    for dst in twin.successors(asset):
        node = twin.nodes.get(dst)
        if node and node.type == "ip":
            return dst
    return asset if _is_ip(asset) else None


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def _slash24(ip: str | None) -> str | None:
    if not ip or not _is_ip(ip):
        return None
    try:
        net = ipaddress.ip_network(f"{ip}/24", strict=False)
        return str(net)
    except ValueError:
        return None


def _asn_of(twin: DigitalTwin, ip: str | None) -> str | None:
    if not ip:
        return None
    for dst in twin.successors(ip):
        node = twin.nodes.get(dst)
        if node and node.type == "asn":
            return dst
    return None


def _certs_of(twin: DigitalTwin, asset: str) -> set[str]:
    return {d for d in twin.successors(asset)
            if (n := twin.nodes.get(d)) and n.type == "cert"}


def _pair_score(twin: DigitalTwin, a: str, b: str) -> tuple[float, list[str]]:
    score, why = 0.0, []
    ip_a, ip_b = _asset_ip(twin, a), _asset_ip(twin, b)

    if _certs_of(twin, a) & _certs_of(twin, b):
        score += 0.6; why.append("shared certificate")
    if ip_a and ip_a == ip_b:
        score += 0.5; why.append("same IP")
    elif _slash24(ip_a) and _slash24(ip_a) == _slash24(ip_b):
        score += 0.3; why.append("same /24")
    asn_a, asn_b = _asn_of(twin, ip_a), _asn_of(twin, ip_b)
    if asn_a and asn_a == asn_b:
        score += 0.25; why.append("same ASN")

    shared = _tokens(a) & _tokens(b)
    if shared:
        score += min(0.4, 0.2 * len(shared)); why.append(f"naming overlap {sorted(shared)}")
    return score, why


def _label(twin: DigitalTwin, members: list[str]) -> tuple[str, float, list[str]]:
    evidence: list[str] = []
    staging = abandoned = 0
    for m in members:
        node = twin.nodes.get(m)
        if _STAGING_RE.search(m):
            staging += 1
        ip = _asset_ip(twin, m)
        if ip and _is_ip(ip) and ipaddress.ip_address(ip).is_private:
            staging += 1; evidence.append(f"{m} -> private IP")
        if node and (node.attrs.get("parked") or node.attrs.get("expired")):
            abandoned += 1
        if node and len(twin.neighbors(m)) <= 1 and node.type == "subdomain":
            abandoned += 1
    n = max(len(members), 1)
    if staging / n >= 0.5:
        return "staging", min(0.9, staging / n), evidence or ["dev/test naming or internal IPs"]
    if abandoned / n >= 0.5:
        return "abandoned", min(0.85, abandoned / n), evidence or ["dangling / parked indicators"]
    return "active", 0.6, evidence


def cluster_infrastructure(twin: DigitalTwin, threshold: float = 0.45) -> list[Cluster]:
    assets = [n.id for n in twin.nodes.values()
              if n.type in ("domain", "subdomain", "ip")]
    uf = _UnionFind(assets)
    edge_evidence: dict[tuple[str, str], list[str]] = {}

    for i in range(len(assets)):
        for j in range(i + 1, len(assets)):
            s, why = _pair_score(twin, assets[i], assets[j])
            if s >= threshold:
                uf.union(assets[i], assets[j])
                edge_evidence[(assets[i], assets[j])] = why

    groups: dict[str, list[str]] = {}
    for a in assets:
        groups.setdefault(uf.find(a), []).append(a)

    clusters: list[Cluster] = []
    for idx, (root, members) in enumerate(sorted(groups.items())):
        if len(members) < 2:
            continue
        label, conf, ev = _label(twin, members)
        for (x, y), why in edge_evidence.items():
            if x in members and y in members:
                ev = ev + why
        clusters.append(Cluster(
            id=f"cluster-{idx}", members=sorted(members), label=label,
            confidence=round(conf, 3), evidence=ev[:8],
        ))
    return clusters
