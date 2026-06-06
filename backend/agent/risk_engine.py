from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import ValidationError

from backend.models.schemas import Finding, ReconReport


def score(all_findings: list[Finding]) -> Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
    if any(f.severity == "CRITICAL" for f in all_findings):
        return "CRITICAL"
    if any(f.severity == "HIGH" for f in all_findings):
        return "HIGH"
    if any(f.severity == "MEDIUM" for f in all_findings):
        return "MEDIUM"
    return "LOW"


def build_report(
    target: str,
    target_type: str,
    module_results: list[dict],
) -> ReconReport:
    all_findings: list[Finding] = []
    modules: dict = {}

    for result in module_results:
        name = result.get("module", "unknown")
        raw_findings = result.get("findings", [])
        parsed: list[Finding] = []
        for f in raw_findings:
            try:
                parsed.append(Finding(**f) if isinstance(f, dict) else f)
            except (ValidationError, Exception):
                pass
        all_findings.extend(parsed)
        modules[name] = {
            "data": result.get("data", {}),
            "findings": [f.model_dump() for f in parsed],
        }

    return ReconReport(
        target=target,
        target_type=target_type,
        risk_level=score(all_findings),
        findings=all_findings,
        modules=modules,
        timestamp=datetime.now(timezone.utc),
    )
