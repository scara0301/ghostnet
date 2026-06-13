"""Adversarial simulation: attack-path search and confidence propagation."""
from __future__ import annotations

from backend.intel.adversary import simulate_attack_paths
from backend.intel.graph import DigitalTwin


def test_path_to_crown_jewel_is_found():
    twin = DigitalTwin()
    twin.upsert_node("corp.com", "domain")
    twin.upsert_node("admin.corp.com", "subdomain", open_ports=[22, 3389])
    twin.upsert_edge("admin.corp.com", "corp.com", "subdomain_of")
    paths = simulate_attack_paths(twin)
    assert paths, "an admin host with RDP/SSH should yield an attack path"
    top = paths[0]
    assert "admin" in top.objective
    assert 0.0 < top.path_confidence <= 1.0
    assert top.impact in ("HIGH", "CRITICAL")


def test_path_confidence_is_product_of_steps():
    twin = DigitalTwin()
    twin.upsert_node("corp.com", "domain")
    twin.upsert_node("vpn.corp.com", "subdomain", open_ports=[22])
    twin.upsert_edge("vpn.corp.com", "corp.com", "subdomain_of")
    paths = simulate_attack_paths(twin)
    assert paths
    product = 1.0
    for step in paths[0].steps:
        product *= step.confidence
    assert abs(product - paths[0].path_confidence) < 1e-6


def test_techniques_are_mapped():
    twin = DigitalTwin()
    twin.upsert_node("corp.com", "domain")
    twin.upsert_node("db.corp.com", "subdomain", open_ports=[6379])
    twin.upsert_edge("db.corp.com", "corp.com", "subdomain_of")
    paths = simulate_attack_paths(twin)
    assert paths
    assert any("T1" in s.technique for s in paths[0].steps)
    assert paths[0].impact == "CRITICAL"     # db objective


def test_empty_twin_yields_no_paths():
    assert simulate_attack_paths(DigitalTwin()) == []
