"""Digital Twin graph: ingestion, idempotent merge, serialisation roundtrip."""
from __future__ import annotations

from backend.intel.graph import DigitalTwin


def _dns_result():
    return {
        "module": "dns",
        "data": {"A": ["1.2.3.4"], "MX": ["10 mail.example.com."],
                 "NS": ["ns1.example.com."], "AAAA": []},
        "findings": [],
    }


def test_ingest_dns_creates_typed_nodes_and_edges():
    twin = DigitalTwin()
    twin.ingest_module("example.com", _dns_result())
    assert "example.com" in twin.nodes
    assert twin.nodes["example.com"].type == "domain"
    assert "1.2.3.4" in twin.nodes and twin.nodes["1.2.3.4"].type == "ip"
    assert twin.has_edge("example.com", "1.2.3.4", "resolves_to")
    assert any(e.type == "mx_for" for e in twin.edges.values())
    assert any(e.type == "uses_ns" for e in twin.edges.values())


def test_merge_is_idempotent():
    twin = DigitalTwin()
    twin.ingest_module("example.com", _dns_result())
    n_nodes, n_edges = len(twin.nodes), len(twin.edges)
    twin.ingest_module("example.com", _dns_result())  # same scan again
    assert len(twin.nodes) == n_nodes
    assert len(twin.edges) == n_edges


def test_confidence_is_max_on_merge():
    twin = DigitalTwin()
    twin.upsert_node("h", "subdomain", confidence=0.4)
    twin.upsert_node("h", "subdomain", confidence=0.9)
    assert twin.nodes["h"].confidence == 0.9


def test_serialisation_roundtrip():
    twin = DigitalTwin()
    twin.ingest_module("example.com", _dns_result())
    twin.ingest_module("example.com", {"module": "crt",
                                       "data": {"subdomains": ["api.example.com"]},
                                       "findings": []})
    restored = DigitalTwin.from_dict(twin.to_dict())
    assert len(restored.nodes) == len(twin.nodes)
    assert len(restored.edges) == len(twin.edges)
    assert restored.has_edge("api.example.com", "example.com", "subdomain_of")


def test_ip_target_root_is_ip_node():
    twin = DigitalTwin()
    twin.ingest_module("8.8.8.8", {"module": "geo",
                                   "data": {"query": "8.8.8.8", "as": "AS15169",
                                            "org": "Google"}, "findings": []})
    assert twin.nodes["8.8.8.8"].type == "ip"
    assert any(n.type == "asn" for n in twin.nodes.values())


def test_ingest_dns_tolerates_empty_or_whitespace_mx():
    # Regression (H1): malformed/partial DoH answers can yield empty or
    # whitespace-only MX values; ingestion must skip them, never raise, so one
    # bad record can't abort the whole analyst run.
    twin = DigitalTwin()
    twin.ingest_module("example.com", {
        "module": "dns",
        "data": {"A": ["1.2.3.4"], "MX": ["", "   ", "10 mail.example.com."]},
        "findings": [],
    })
    assert "mail.example.com" in twin.nodes                  # the valid MX survived
    assert any(e.type == "mx_for" for e in twin.edges.values())
    assert "" not in twin.nodes                              # empty value skipped
