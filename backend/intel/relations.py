"""Hidden-relationship prediction over the Digital Twin.

"Predict hidden relationships" is link prediction on the twin graph. We ship a
classical, dependency-free baseline today -- the Adamic-Adar index, which scores
an unobserved pair by their shared neighbours, weighting rare shared neighbours
more (two subdomains sharing an obscure nameserver is stronger evidence than
sharing a popular CDN IP). Every predicted edge carries sub-1.0 confidence and
``predicted`` type, so inferred knowledge is never confused with observed.

The neural upgrade (a GraphSAGE / R-GCN link predictor) is specified in the
architecture doc and slots in behind ``predict_hidden_edges`` unchanged: it
returns the same ``Edge`` list, just with learned embeddings replacing the
hand-built index.
"""
from __future__ import annotations

import math

from backend.intel.graph import DigitalTwin
from backend.intel.schemas import Edge

_LINKABLE = ("subdomain", "ip", "domain", "cert", "asn", "nameserver")


def adamic_adar(twin: DigitalTwin, a: str, b: str) -> tuple[float, list[str]]:
    na, nb = twin.neighbors(a), twin.neighbors(b)
    shared = na & nb
    score = 0.0
    for c in shared:
        deg = len(twin.neighbors(c))
        if deg > 1:
            score += 1.0 / math.log(deg)
    return score, sorted(shared)


def predict_hidden_edges(twin: DigitalTwin, top_k: int = 10,
                         min_confidence: float = 0.2) -> list[Edge]:
    nodes = [n.id for n in twin.nodes.values() if n.type in _LINKABLE]
    candidates: list[tuple[float, str, str, list[str]]] = []

    for i in range(len(nodes)):
        for j in range(i + 1, len(nodes)):
            a, b = nodes[i], nodes[j]
            if twin.has_edge(a, b) or twin.has_edge(b, a):
                continue
            score, shared = adamic_adar(twin, a, b)
            if score > 0:
                candidates.append((score, a, b, shared))

    if not candidates:
        return []
    top = max(s for s, *_ in candidates)
    edges: list[Edge] = []
    for score, a, b, shared in sorted(candidates, reverse=True)[:top_k]:
        conf = min(0.85, score / top)            # normalise to [0, 0.85]
        if conf < min_confidence:
            continue
        edges.append(Edge(
            src=a, dst=b, type="predicted", confidence=round(conf, 3),
            attrs={"method": "adamic_adar", "shared": shared[:5],
                   "interpretation": "likely co-owned / co-hosted (unobserved)"},
        ))
    return edges
