"""Analyst WebSocket endpoint — framing + terminal DONE with intel product.

The recon collector is monkeypatched so the endpoint is exercised fully offline.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

import backend.main as mainmod

_CANNED = {
    "dns": {"module": "dns", "data": {"A": ["1.2.3.4"], "MX": [], "TXT": [], "DMARC": ""}, "findings": []},
    "crt": {"module": "crt", "data": {"subdomains": ["dev.x.com"]}, "findings": []},
    "geo": {"module": "geo", "data": {"query": "1.2.3.4", "hosting": False}, "findings": []},
    "otx": {"module": "otx", "data": {"pulse_count": 0}, "findings": []},
    "rep": {"module": "rep", "data": {"open_ports": []}, "findings": []},
    "whois": {"module": "whois", "data": {"status": ["clientDeleteProhibited"]}, "findings": []},
}


async def _fake_default_runner(name, target, client):
    return _CANNED[name]


def test_analyst_ws_streams_and_finishes(monkeypatch):
    monkeypatch.setattr(mainmod, "default_runner", _fake_default_runner)
    client = TestClient(mainmod.app)
    with client.websocket_connect("/ws/analyst") as ws:
        ws.send_text(json.dumps({"target": "x.com", "target_type": "domain"}))
        events = []
        while True:
            ev = json.loads(ws.receive_text())
            events.append(ev)
            if ev["tag"] == "DONE":
                break

    tags = [e["tag"] for e in events]
    assert "RUN" in tags                       # streamed live collection
    assert tags[-1] == "DONE"
    report = events[-1]["data"]
    assert report["target"] == "x.com"
    assert "posture" in report and report["posture"]["theta_mean"] is not None
    assert any(h["id"] == "H1" for h in report["hypotheses"])
    assert "modules_run" in report and report["modules_run"]


def test_analyst_ws_invalid_target_emits_done():
    client = TestClient(mainmod.app)
    with client.websocket_connect("/ws/analyst") as ws:
        ws.send_text(json.dumps({"target": "x", "target_type": "bogus"}))
        first = json.loads(ws.receive_text())
        second = json.loads(ws.receive_text())
    assert first["tag"] == "ERR"
    assert second["tag"] == "DONE"
