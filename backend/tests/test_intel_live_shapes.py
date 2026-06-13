"""Contract tests against the *real* recon-module output shapes.

The canned data in other intel tests is idealised. These tests use the exact
shapes the live modules emit (DMARC as a list, registrar as a vcardArray, rep's
flat open_ports, whois expiry strings) so the live-scan path cannot silently
regress the way it did before this suite existed.
"""
from __future__ import annotations

from datetime import datetime, timezone

from backend.intel.bayes import observe_controls
from backend.intel.evolution import forecast_all
from backend.intel.graph import DigitalTwin
from backend.intel.store import SnapshotStore


def test_observe_controls_handles_dmarc_as_list():
    # dns_module returns DMARC as a list of TXT strings, not a string.
    results = [{"module": "dns", "data": {
        "A": ["1.2.3.4"], "MX": ["10 mail.x.com."],
        "TXT": ["v=spf1 -all"], "DMARC": ["v=DMARC1; p=reject"]}}]
    obs = observe_controls(results)
    assert obs["dmarc"] is True
    assert obs["dmarc_enforced"] is True
    assert obs["spf"] is True


def test_whois_ingest_captures_expiry_and_guards_vcard_registrar():
    twin = DigitalTwin()
    twin.ingest_module("example.com", {"module": "whois", "data": {
        "registrar": [["version", {}, "text", "1.0"]],     # vcardArray, NOT a str
        "expiry": "2027-01-01T00:00:00Z",
        "status": ["clientTransferProhibited"]}, "findings": []})
    assert twin.nodes["example.com"].attrs["expiry"] == "2027-01-01T00:00:00+00:00"
    # The vcardArray registrar must not create a malformed org node.
    assert not any(n.type == "org" for n in twin.nodes.values())


def test_rep_ingest_attaches_open_ports_for_adversary():
    twin = DigitalTwin()
    twin.ingest_module("1.2.3.4", {"module": "rep", "data": {
        "open_ports": [22, 3389], "nmap": "22/tcp open ssh",
        "hostsearch": "", "reversedns": ""}, "findings": []})
    assert twin.nodes["1.2.3.4"].attrs["open_ports"] == [22, 3389]


def test_forecast_all_picks_up_expiry_from_twin():
    twin = DigitalTwin()
    twin.ingest_module("x.com", {"module": "dns", "data": {"A": ["1.2.3.4"]}, "findings": []})
    twin.ingest_module("x.com", {"module": "whois", "data": {
        "expiry": "2027-01-01T00:00:00Z", "registrar": [["v"]], "status": []}, "findings": []})
    history = [{"ts": datetime(2026, 1, 1, tzinfo=timezone.utc), "twin": twin}]
    forecasts = forecast_all("x.com", history)
    assert any(f.kind == "domain_expiry" for f in forecasts)


def test_store_roundtrip_preserves_expiry_attr():
    store = SnapshotStore(":memory:")
    twin = DigitalTwin()
    twin.ingest_module("x.com", {"module": "dns", "data": {"A": ["1.2.3.4"]}, "findings": []})
    twin.nodes["x.com"].attrs["expiry"] = "2027-01-01T00:00:00+00:00"
    store.save("x.com", twin)
    restored = store.history("x.com")[-1]["twin"]
    assert restored.nodes["x.com"].attrs["expiry"] == "2027-01-01T00:00:00+00:00"
    store.close()
