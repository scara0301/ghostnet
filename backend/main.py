from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.agent.orchestrator import run_pipeline
from backend.intel.agent import run_analysis
from backend.intel.registry import default_runner
from backend.intel.store import SnapshotStore
from backend.models.schemas import TargetRequest, WSEvent

app = FastAPI(title="ghostnet")


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = os.environ.get(name, "")
    items = [x.strip() for x in raw.split(",") if x.strip()]
    return items or default


# CORS is scoped to the app's own origin by default (the frontend is served
# same-origin by this app). Override with GHOSTNET_CORS_ORIGINS for external
# clients. Note: CORS does NOT govern the WebSocket handshake — that is guarded
# separately by the Origin allowlist below.
_CORS_ORIGINS = _env_list(
    "GHOSTNET_CORS_ORIGINS",
    ["http://localhost:8000", "http://127.0.0.1:8000"],
)

# WebSocket Origin allowlist (hostnames). A browser always sends Origin on the
# WS handshake, so this blocks cross-site WebSocket hijacking; non-browser
# clients (curl, server-to-server, tests) send no Origin and are allowed.
_ALLOWED_WS_HOSTS = set(_env_list(
    "GHOSTNET_ALLOWED_ORIGINS",
    ["localhost", "127.0.0.1", "::1"],
))

app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def _origin_allowed(ws: WebSocket) -> bool:
    """Reject cross-site WebSocket connections. Missing Origin (non-browser
    clients) is permitted; a present Origin must resolve to an allowed host."""
    origin = ws.headers.get("origin")
    if origin is None:
        return True
    host = (urlparse(origin).hostname or "").strip("[]")
    return host in _ALLOWED_WS_HOSTS


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.websocket("/ws/recon")
async def websocket_endpoint(ws: WebSocket) -> None:
    if not _origin_allowed(ws):
        await ws.close(code=1008)               # policy violation, before accept
        return
    await ws.accept()
    try:
        raw = await ws.receive_text()
        payload = json.loads(raw)
        req = TargetRequest(**payload)

        async def send(event: WSEvent) -> None:
            await ws.send_text(event.model_dump_json())

        await run_pipeline(req.target, req.target_type, send)
    except WebSocketDisconnect:
        pass
    except Exception:
        # Generic message only — never leak exception internals (paths, etc.).
        err = WSEvent(tag="ERR", module="server", message="invalid request or internal error")
        try:
            await ws.send_text(err.model_dump_json())
            done = WSEvent(tag="DONE", module="server", data={})
            await ws.send_text(done.model_dump_json())
        except Exception:
            pass


@app.websocket("/ws/analyst")
async def analyst_endpoint(ws: WebSocket) -> None:
    """Autonomous analyst: streams collection decisions, ends with the full
    intelligence product (posture, clusters, forecasts, attack paths, actors,
    predicted edges, hypothesis ledger) rather than a flat findings list.
    """
    if not _origin_allowed(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    try:
        payload = json.loads(await ws.receive_text())
        req = TargetRequest(**payload)

        async def send(event: WSEvent) -> None:
            await ws.send_text(event.model_dump_json())

        async with httpx.AsyncClient(timeout=20.0) as client:
            async def traced_runner(name: str, target: str, c) -> dict:
                await send(WSEvent(tag="RUN", module=name,
                                   message=f"analyst tasking collection: {name}"))
                result = await default_runner(name, target, c)
                await send(WSEvent(tag="OK", module=name,
                                   message=f"{name} collected",
                                   data=result.get("data")))
                return result

            store = SnapshotStore()              # persists to reports/ghostnet.db
            try:
                report = await run_analysis(req.target, req.target_type,
                                            run_module=traced_runner, client=client,
                                            store=store)
            finally:
                store.close()

        for decision in report.decisions:
            await send(WSEvent(tag="WARN" if decision.action == "request_collection" else "OK",
                               module="analyst", message=decision.reason,
                               data=decision.model_dump(mode="json")))
        await send(WSEvent(tag="DONE", module="analyst",
                           data=report.model_dump(mode="json")))
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await ws.send_text(WSEvent(tag="ERR", module="server",
                                       message="invalid request or internal error").model_dump_json())
            await ws.send_text(WSEvent(tag="DONE", module="server", data={}).model_dump_json())
        except Exception:
            pass


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
