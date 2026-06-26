"""Temporal snapshot store: persistence + history retrieval (in-memory SQLite)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.intel.graph import DigitalTwin
from backend.intel.store import SnapshotStore


def test_save_and_retrieve_history():
    store = SnapshotStore(":memory:")
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)

    twin1 = DigitalTwin()
    twin1.upsert_node("a.x.com", "subdomain")
    store.save("x.com", twin1, posture=0.4, findings=2, ts=t0)

    twin2 = DigitalTwin()
    twin2.upsert_node("a.x.com", "subdomain")
    twin2.upsert_node("b.x.com", "subdomain")
    store.save("x.com", twin2, posture=0.5, findings=3, ts=t0 + timedelta(days=10))

    history = store.history("x.com")
    assert len(history) == 2
    assert history[0]["ts"] < history[1]["ts"]
    assert len(history[1]["twin"].nodes) == 2          # roundtripped graph
    assert store.latest("x.com")["findings"] == 3
    store.close()


def test_history_is_target_scoped():
    store = SnapshotStore(":memory:")
    store.save("x.com", DigitalTwin())
    store.save("y.com", DigitalTwin())
    assert len(store.history("x.com")) == 1
    assert store.latest("z.com") is None
    store.close()


def test_history_returns_most_recent_within_limit():
    # Regression (M2): once a target exceeds `limit` snapshots, history() must
    # return the NEWEST N in ascending order (not the oldest N), so forecasts
    # diff recent history and latest() is the newest snapshot.
    store = SnapshotStore(":memory:")
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for i in range(60):
        store.save("x.com", DigitalTwin(), findings=i, ts=t0 + timedelta(days=i))
    h = store.history("x.com", limit=50)
    assert len(h) == 50
    assert h[0]["ts"] < h[-1]["ts"]                  # ascending chronological
    assert h[0]["findings"] == 10 and h[-1]["findings"] == 59   # newest 50 retained
    assert store.latest("x.com")["findings"] == 59
    store.close()
