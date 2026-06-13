"""The Digital Twin: a typed, mergeable graph of an organization's footprint.

This is the shared substrate. Recon modules *contribute* to it, the inference
engines *read* from it, and the temporal store *snapshots* it. The graph is a
plain in-memory adjacency structure (no third-party graph lib) so it serialises
cleanly to SQLite/JSON and stays dependency-free.

Key design choice: merging is idempotent and confidence-aware. Re-ingesting the
same scan does not duplicate nodes; it refreshes ``last_seen`` and takes the max
confidence. That is what lets the twin be "continuously updated" rather than
rebuilt per scan.
"""
from __future__ import annotations

import ipaddress
from collections import defaultdict

from backend.intel.schemas import Edge, EntityType, Node, RelType, now

INTERNET = "internet:0.0.0.0/0"   # synthetic root node for adversarial sim


class DigitalTwin:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: dict[tuple[str, str, str], Edge] = {}
        self._out: dict[str, set[str]] = defaultdict(set)
        self._in: dict[str, set[str]] = defaultdict(set)

    # -- mutation -------------------------------------------------------------

    def upsert_node(self, id: str, type: EntityType, label: str = "",
                    confidence: float = 1.0, **attrs) -> Node:
        existing = self.nodes.get(id)
        if existing is None:
            node = Node(id=id, type=type, label=label or id,
                        confidence=confidence, attrs=dict(attrs))
            self.nodes[id] = node
            return node
        existing.last_seen = now()
        existing.confidence = max(existing.confidence, confidence)
        existing.attrs.update({k: v for k, v in attrs.items() if v is not None})
        if label:
            existing.label = label
        return existing

    def upsert_edge(self, src: str, dst: str, type: RelType,
                    confidence: float = 1.0, **attrs) -> Edge:
        key = (src, dst, type)
        existing = self.edges.get(key)
        if existing is None:
            edge = Edge(src=src, dst=dst, type=type,
                        confidence=confidence, attrs=dict(attrs))
            self.edges[key] = edge
        else:
            existing.last_seen = now()
            existing.confidence = max(existing.confidence, confidence)
            existing.attrs.update(attrs)
            edge = existing
        self._out[src].add(dst)
        self._in[dst].add(src)
        return edge

    # -- queries --------------------------------------------------------------

    def neighbors(self, id: str) -> set[str]:
        return self._out[id] | self._in[id]

    def successors(self, id: str) -> set[str]:
        return set(self._out[id])

    def of_type(self, type: EntityType) -> list[Node]:
        return [n for n in self.nodes.values() if n.type == type]

    def edges_of(self, type: RelType) -> list[Edge]:
        return [e for e in self.edges.values() if e.type == type]

    def has_edge(self, src: str, dst: str, type: RelType | None = None) -> bool:
        if type is not None:
            return (src, dst, type) in self.edges
        return any(s == src and d == dst for s, d, _ in self.edges)

    # -- ingestion of recon module output ------------------------------------

    def ingest_module(self, target: str, result: dict) -> None:
        """Project a single module's ``{module, data, findings}`` into the twin.

        Each branch is deliberately defensive: modules can return partial data,
        and the twin must never raise on a missing key.
        """
        module = result.get("module", "")
        data = result.get("data") or {}
        root = self._root(target)

        if module == "dns":
            for a in data.get("A", []) or []:
                self.upsert_node(a, "ip", a)
                self.upsert_edge(root, a, "resolves_to")
            for aaaa in data.get("AAAA", []) or []:
                self.upsert_node(aaaa, "ip", aaaa)
                self.upsert_edge(root, aaaa, "resolves_to")
            for mx in data.get("MX", []) or []:
                host = mx.split()[-1].rstrip(".") if isinstance(mx, str) else str(mx)
                self.upsert_node(host, "mx", host)
                self.upsert_edge(host, root, "mx_for")
            for ns in data.get("NS", []) or []:
                ns = ns.rstrip(".")
                self.upsert_node(ns, "nameserver", ns)
                self.upsert_edge(root, ns, "uses_ns")

        elif module == "crt":
            for sub in data.get("subdomains", []) or []:
                self.upsert_node(sub, "subdomain", sub)
                self.upsert_edge(sub, root, "subdomain_of")

        elif module == "geo":
            asn = data.get("as") or data.get("asn")
            ip = data.get("query") or target
            if ip:
                self.upsert_node(ip, "ip", ip)
            if asn:
                self.upsert_node(f"asn:{asn}", "asn", str(asn))
                if ip:
                    self.upsert_edge(ip, f"asn:{asn}", "announced_by")
            org = data.get("org") or data.get("isp")
            if org:
                self.upsert_node(f"org:{org}", "org", org)
                if ip:
                    self.upsert_edge(ip, f"org:{org}", "owned_by", confidence=0.6)

        elif module == "whois":
            registrar = data.get("registrar")
            if registrar:
                self.upsert_node(f"registrar:{registrar}", "org", registrar)
                self.upsert_edge(root, f"registrar:{registrar}", "same_registrar")

        elif module == "rep":
            for host in data.get("hosts", []) or []:
                self.upsert_node(host, "subdomain", host)
                self.upsert_edge(host, root, "subdomain_of", confidence=0.7)

    def _root(self, target: str) -> str:
        try:
            ipaddress.ip_address(target)
            self.upsert_node(target, "ip", target)
            return target
        except ValueError:
            domain = target.split("@")[-1] if "@" in target else target
            self.upsert_node(domain, "domain", domain)
            return domain

    # -- serialisation --------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "nodes": [n.model_dump(mode="json") for n in self.nodes.values()],
            "edges": [e.model_dump(mode="json") for e in self.edges.values()],
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "DigitalTwin":
        twin = cls()
        for n in payload.get("nodes", []):
            node = Node(**n)
            twin.nodes[node.id] = node
        for e in payload.get("edges", []):
            edge = Edge(**e)
            twin.edges[(edge.src, edge.dst, edge.type)] = edge
            twin._out[edge.src].add(edge.dst)
            twin._in[edge.dst].add(edge.src)
        return twin

    def stats(self) -> dict:
        by_type: dict[str, int] = defaultdict(int)
        for n in self.nodes.values():
            by_type[n.type] += 1
        return {"nodes": len(self.nodes), "edges": len(self.edges), "by_type": dict(by_type)}
