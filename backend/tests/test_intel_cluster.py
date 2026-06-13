"""Infrastructure clustering: ownership grouping + lifecycle labelling."""
from __future__ import annotations

from backend.intel.cluster import cluster_infrastructure
from backend.intel.graph import DigitalTwin


def test_same_ip_assets_cluster_together():
    twin = DigitalTwin()
    for host in ("api.example.com", "web.example.com"):
        twin.upsert_node(host, "subdomain")
        twin.upsert_node("1.2.3.4", "ip")
        twin.upsert_edge(host, "1.2.3.4", "resolves_to")
    clusters = cluster_infrastructure(twin)
    assert any({"api.example.com", "web.example.com"} <= set(c.members) for c in clusters)


def test_staging_cluster_is_labelled():
    twin = DigitalTwin()
    for host in ("dev1.corp.com", "dev2.corp.com"):
        twin.upsert_node(host, "subdomain")
        twin.upsert_node("10.0.0.5", "ip")
        twin.upsert_edge(host, "10.0.0.5", "resolves_to")
    clusters = cluster_infrastructure(twin)
    staging = [c for c in clusters if c.label == "staging"]
    assert staging, "dev*.corp.com on a private IP should be a staging cluster"
    assert staging[0].confidence > 0.0


def test_unrelated_assets_do_not_cluster():
    twin = DigitalTwin()
    twin.upsert_node("alpha.com", "domain")
    twin.upsert_node("9.9.9.9", "ip")
    twin.upsert_edge("alpha.com", "9.9.9.9", "resolves_to")
    twin.upsert_node("beta.net", "domain")
    twin.upsert_node("4.4.4.4", "ip")
    twin.upsert_edge("beta.net", "4.4.4.4", "resolves_to")
    clusters = cluster_infrastructure(twin)
    # No shared signal -> no multi-member cluster.
    assert all(not ({"alpha.com", "beta.net"} <= set(c.members)) for c in clusters)
