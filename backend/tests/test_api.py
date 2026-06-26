"""API tests — /health and the /ws/recon WebSocket endpoint.

The orchestrator is patched out for the happy-path WebSocket test so the
endpoint's framing logic is verified without live recon. The validation-failure
test uses the real path to confirm a terminal DONE is always emitted.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import backend.main as mainmod
from backend.models.schemas import WSEvent


def test_health():
    client = TestClient(mainmod.app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_websocket_streams_events(monkeypatch):
    async def fake_pipeline(target, target_type, send):
        await send(WSEvent(tag="RUN", module="dns", message="Starting dns..."))
        await send(WSEvent(tag="WARN", module="dns", message="Missing SPF record"))
        await send(WSEvent(tag="DONE", module="engine", data={"risk_level": "MEDIUM", "findings": []}))

    monkeypatch.setattr(mainmod, "run_pipeline", fake_pipeline)

    client = TestClient(mainmod.app)
    with client.websocket_connect("/ws/recon") as ws:
        ws.send_text(json.dumps({"target": "example.com", "target_type": "domain"}))
        events = [json.loads(ws.receive_text()) for _ in range(3)]

    tags = [e["tag"] for e in events]
    assert tags == ["RUN", "WARN", "DONE"]
    assert events[-1]["data"]["risk_level"] == "MEDIUM"


def test_websocket_invalid_target_type_still_emits_done():
    # Real path: TargetRequest validation fails -> ERR then DONE (no network).
    client = TestClient(mainmod.app)
    with client.websocket_connect("/ws/recon") as ws:
        ws.send_text(json.dumps({"target": "x", "target_type": "bogus"}))
        first = json.loads(ws.receive_text())
        second = json.loads(ws.receive_text())

    assert first["tag"] == "ERR"
    assert first["module"] == "server"
    assert second["tag"] == "DONE"


def test_websocket_malformed_json_emits_done():
    client = TestClient(mainmod.app)
    with client.websocket_connect("/ws/recon") as ws:
        ws.send_text("not json at all")
        first = json.loads(ws.receive_text())
        second = json.loads(ws.receive_text())

    assert first["tag"] == "ERR"
    assert second["tag"] == "DONE"


def test_websocket_rejects_cross_site_origin():
    # Hardening: a browser always sends Origin on the WS handshake; a cross-site
    # page must be refused (blocks cross-site WebSocket hijacking).
    client = TestClient(mainmod.app)
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/ws/recon", headers={"origin": "http://evil.example"}
        ) as ws:
            ws.receive_text()


def test_websocket_allows_localhost_origin(monkeypatch):
    async def fake_pipeline(target, target_type, send):
        await send(WSEvent(tag="DONE", module="engine", data={}))

    monkeypatch.setattr(mainmod, "run_pipeline", fake_pipeline)
    client = TestClient(mainmod.app)
    with client.websocket_connect(
        "/ws/recon", headers={"origin": "http://localhost:8000"}
    ) as ws:
        ws.send_text(json.dumps({"target": "example.com", "target_type": "domain"}))
        assert json.loads(ws.receive_text())["tag"] == "DONE"
