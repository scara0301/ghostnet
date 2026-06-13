from __future__ import annotations

import json
from pathlib import Path

import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.agent.orchestrator import run_pipeline
from backend.intel.agent import run_analysis
from backend.intel.registry import default_runner
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


@app.websocket("/ws/analyst")
async def analyst_endpoint(ws: WebSocket) -> None:
    """Autonomous analyst: streams collection decisions, ends with the full
    intelligence product (posture, clusters, forecasts, attack paths, actors,
    predicted edges, hypothesis ledger) rather than a flat findings list.
    """
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

            report = await run_analysis(req.target, req.target_type,
                                        run_module=traced_runner, client=client)

        for decision in report.decisions:
            await send(WSEvent(tag="WARN" if decision.action == "request_collection" else "OK",
                               module="analyst", message=decision.reason,
                               data=decision.model_dump(mode="json")))
        await send(WSEvent(tag="DONE", module="analyst",
                           data=report.model_dump(mode="json")))
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        try:
            await ws.send_text(WSEvent(tag="ERR", module="server", message=str(exc)).model_dump_json())
            await ws.send_text(WSEvent(tag="DONE", module="server", data={}).model_dump_json())
        except Exception:
            pass


app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
