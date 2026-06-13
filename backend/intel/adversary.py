"""Adversarial Simulation Engine — how would an attacker pivot through this?

We turn the passively-discovered Digital Twin into an attack graph and search it
the way an attacker reasons: from the open internet toward "crown jewel" assets
(admin panels, internal/staging hosts, databases, mail infrastructure).

Each edge gets an *exploitability weight* in (0,1] derived only from observed
signals -- a dangerous open port (RDP/SMB/SSH/DB), a weak-TLS host, an admin-ish
hostname, a shared certificate that links a hardened host to a soft one. The
"easiest" path is the one whose product of edge confidences is highest, which we
find with Dijkstra over -log(confidence) (turning a max-product problem into a
min-sum shortest path). Each emitted path is a hypothesis with a calibrated
confidence and a mapped technique, not a definite exploit -- this is simulation,
never live attack.
"""
from __future__ import annotations

import math
import re
from heapq import heappop, heappush

from backend.intel.graph import INTERNET, DigitalTwin
from backend.intel.schemas import AttackPath, AttackStep, Severity

_ADMIN_RE = re.compile(r"(admin|vpn|portal|jenkins|gitlab|grafana|kibana|phpmyadmin|rdp|citrix)")
_CROWN_RE = re.compile(r"(admin|internal|db|database|sql|backup|vault|secret|staging|jenkins|vpn)")
_DANGER_PORTS = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 445: "SMB",
                 3389: "RDP", 5900: "VNC", 6379: "Redis", 27017: "MongoDB", 3306: "MySQL"}


def _exposure(node, twin: DigitalTwin) -> tuple[float, str]:
    """Per-node intrinsic exploitability and the dominant reason."""
    attrs = node.attrs or {}
    ports = attrs.get("open_ports") or attrs.get("ports") or []
    danger = [p for p in ports if p in _DANGER_PORTS]
    score, reason = 0.1, "exposed surface"
    if danger:
        score = max(score, 0.7)
        reason = f"open {_DANGER_PORTS[danger[0]]} ({danger[0]})"
    if _ADMIN_RE.search(node.id):
        score = max(score, 0.55); reason = "admin/management hostname"
    if attrs.get("weak_tls") or attrs.get("no_tls"):
        score = max(score, 0.5); reason = "weak/absent TLS"
    if attrs.get("breached"):
        score = max(score, 0.8); reason = "appears in breach data"
    return score, reason


def _technique(reason: str) -> str:
    r = reason.lower()
    if "ssh" in r or "rdp" in r or "vnc" in r or "telnet" in r:
        return "T1021 Remote Services"
    if "smb" in r:
        return "T1021.002 SMB/Windows Admin Shares"
    if "redis" in r or "mongodb" in r or "mysql" in r:
        return "T1190 Exploit Public-Facing Application (exposed datastore)"
    if "admin" in r or "management" in r:
        return "T1133 External Remote Services / weak admin auth"
    if "tls" in r:
        return "T1557 Adversary-in-the-Middle (weak transport)"
    if "breach" in r:
        return "T1078 Valid Accounts (credential reuse)"
    return "T1595 Active Scanning / surface discovery"


def _build_attack_graph(twin: DigitalTwin) -> dict[str, list[tuple[str, float, str]]]:
    twin.upsert_node(INTERNET, "internet", "internet")
    adj: dict[str, list[tuple[str, float, str]]] = {}

    reachable = [n for n in twin.nodes.values() if n.type in ("ip", "subdomain", "domain")]
    for node in reachable:
        exp, reason = _exposure(node, twin)
        adj.setdefault(INTERNET, []).append((node.id, exp, _technique(reason)))

    # Pivot edges: existing twin relations become lateral-movement edges,
    # weighted by the *destination's* intrinsic exposure (you pivot toward soft
    # targets), boosted when a shared certificate links the two hosts.
    for (src, dst, rtype), edge in twin.edges.items():
        for a, b in ((src, dst), (dst, src)):
            node_b = twin.nodes.get(b)
            if not node_b or node_b.type not in ("ip", "subdomain", "domain"):
                continue
            exp, reason = _exposure(node_b, twin)
            w = exp
            if rtype in ("shares_cert", "subdomain_of"):
                w = min(1.0, w + 0.2); reason += " via shared infra"
            adj.setdefault(a, []).append((b, max(w, 0.05), _technique(reason)))
    return adj


def _crown_jewels(twin: DigitalTwin) -> list[str]:
    jewels = [n.id for n in twin.nodes.values()
              if n.type in ("subdomain", "ip", "domain") and _CROWN_RE.search(n.id)]
    if not jewels:  # fall back to the most-connected internal-ish asset
        cand = [n for n in twin.nodes.values() if n.type in ("subdomain", "ip")]
        cand.sort(key=lambda n: len(twin.neighbors(n.id)), reverse=True)
        jewels = [cand[0].id] if cand else []
    return jewels


def _dijkstra(adj, source: str, target: str):
    """Max-confidence path = min sum of -log(confidence)."""
    dist = {source: 0.0}
    prev: dict[str, tuple[str, float, str]] = {}
    pq = [(0.0, source)]
    seen = set()
    while pq:
        d, u = heappop(pq)
        if u in seen:
            continue
        seen.add(u)
        if u == target:
            break
        for v, conf, tech in adj.get(u, []):
            nd = d - math.log(max(conf, 1e-9))
            if nd < dist.get(v, float("inf")):
                dist[v] = nd
                prev[v] = (u, conf, tech)
                heappush(pq, (nd, v))
    if target not in dist:
        return None, 0.0
    steps, cur, conf_prod = [], target, 1.0
    while cur in prev:
        u, conf, tech = prev[cur]
        steps.append((u, cur, conf, tech))
        conf_prod *= conf
        cur = u
    steps.reverse()
    return steps, conf_prod


def _impact(objective: str) -> Severity:
    o = objective.lower()
    if any(k in o for k in ("db", "database", "sql", "vault", "secret", "backup")):
        return "CRITICAL"
    if any(k in o for k in ("admin", "vpn", "internal", "jenkins")):
        return "HIGH"
    return "MEDIUM"


def simulate_attack_paths(twin: DigitalTwin, max_paths: int = 5) -> list[AttackPath]:
    adj = _build_attack_graph(twin)
    paths: list[AttackPath] = []
    for jewel in _crown_jewels(twin):
        steps, conf = _dijkstra(adj, INTERNET, jewel)
        if not steps:
            continue
        attack_steps = [
            AttackStep(src=s, dst=d, technique=t, confidence=round(c, 3),
                       rationale=f"pivot {s} -> {d}")
            for (s, d, c, t) in steps
        ]
        paths.append(AttackPath(
            entry=INTERNET, objective=jewel, steps=attack_steps,
            path_confidence=round(conf, 4), impact=_impact(jewel),
            rationale=f"{len(attack_steps)}-hop path; weakest links dominate confidence",
        ))
    paths.sort(key=lambda p: p.path_confidence, reverse=True)
    return paths[:max_paths]
