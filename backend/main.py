from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.agent.orchestrator import run_pipeline
from backend.models.schemas import TargetRequest, WSEvent

app = FastAPI(title="ghostnet")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.websocket("/ws/recon")
async def websocket_endpoint(ws: WebSocket) -> None:
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
    except Exception as exc:
        err = WSEvent(tag="ERR", module="server", message=str(exc))
        try:
            await ws.send_text(err.model_dump_json())
            done = WSEvent(tag="DONE", module="server", data={})
            await ws.send_text(done.model_dump_json())
        except Exception:
            pass


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
