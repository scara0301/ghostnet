"""Threat evolution forecasting: Poisson emergence, expiry hazard, cert anomaly."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.intel.evolution import (
    detect_cert_anomaly, detect_migration, forecast_domain_expiry,
    forecast_subdomain_emergence,
)
from backend.intel.graph import DigitalTwin


def _snap(ts, subs=(), ips=(), asns=()):
    twin = DigitalTwin()
    for s in subs:
        twin.upsert_node(s, "subdomain")
    for ip in ips:
        twin.upsert_node(ip, "ip")
    for a in asns:
        twin.upsert_node(a, "asn")
    return {"ts": ts, "twin": twin}


def test_subdomain_emergence_poisson():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    history = [
        _snap(t0, subs=["a.x.com"]),
        _snap(t0 + timedelta(days=10), subs=["a.x.com", "b.x.com", "c.x.com"]),
    ]
    f = forecast_subdomain_emergence(history, horizon_days=30)
    assert f.kind == "subdomain_emergence"
    assert abs(f.expected_count - 6.0) < 1e-6      # lambda 0.2/day * 30
    assert f.probability > 0.9


def test_emergence_needs_history():
    f = forecast_subdomain_emergence([_snap(datetime.now(timezone.utc))])
    assert f.probability == 0.0
    assert f.confidence < 0.3


def test_expiry_hazard_is_monotonic():
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    soon = forecast_domain_expiry(now + timedelta(days=5), now=now, renewal_lead_days=30)
    far = forecast_domain_expiry(now + timedelta(days=300), now=now, renewal_lead_days=30)
    assert soon.probability > 0.5
    assert far.probability < 0.2
    assert soon.probability > far.probability


def test_cert_anomaly_detects_off_cadence():
    regular = detect_cert_anomaly([0.0, 30.0, 60.0, 90.0])
    spike = detect_cert_anomaly([0.0, 30.0, 60.0, 90.0, 200.0])
    assert regular.probability < 0.2
    assert spike.probability > 0.8
    assert detect_cert_anomaly([0.0, 30.0, 60.0], new_issuer=True).probability >= 0.4


def test_migration_detected_on_ip_change():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    history = [
        _snap(t0, ips=["1.1.1.1"]),
        _snap(t0 + timedelta(days=7), ips=["2.2.2.2"]),
    ]
    f = detect_migration(history)
    assert f.probability > 0.4
    assert "delta" in f.detail
