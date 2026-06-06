from __future__ import annotations

import importlib
from collections.abc import Awaitable, Callable

import httpx

from backend.agent import risk_engine
from backend.models.schemas import ReconReport, WSEvent

PIPELINE: dict[str, list[str]] = {
    "domain": ["whois", "dns", "crt", "geo", "otx", "rep"],
    "ip": ["geo", "otx", "rep"],
    "email": ["email", "whois", "dns"],
}

_MODULE_MAP = {
    name: f"backend.modules.{name}_module"
    for name in ("email", "whois", "dns", "crt", "geo", "otx", "rep")
}


async def run_pipeline(
    target: str,
    target_type: str,
    send: Callable[[WSEvent], Awaitable[None]],
) -> ReconReport:
    module_names = PIPELINE.get(target_type, [])
    module_results: list[dict] = []

    async with httpx.AsyncClient(timeout=20.0) as client:
        for name in module_names:
            await send(WSEvent(tag="RUN", module=name, message=f"Starting {name}..."))
            try:
                mod = importlib.import_module(_MODULE_MAP[name])
                result = await mod.run(target, client)
            except Exception as exc:
                await send(WSEvent(tag="ERR", module=name, message=str(exc)))
                result = {"module": name, "data": {}, "findings": []}

            module_results.append(result)

            for finding in result.get("findings", []):
                severity = finding.get("severity", "INFO")
                title = finding.get("title", "Unknown finding")
                tag = "WARN" if severity in ("HIGH", "CRITICAL", "MEDIUM") else "OK"
                await send(WSEvent(
                    tag=tag,
                    module=name,
                    message=title,
                    data=finding,
                ))

            await send(WSEvent(
                tag="OK",
                module=name,
                message=f"{name} complete",
                data=result.get("data"),
            ))

    report = risk_engine.build_report(target, target_type, module_results)
    await send(WSEvent(tag="DONE", module="engine", data=report.model_dump(mode="json")))
    return report
