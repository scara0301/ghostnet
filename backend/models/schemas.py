from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class TargetRequest(BaseModel):
    target: str
    target_type: Literal["domain", "ip", "email"]


class Finding(BaseModel):
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    title: str
    detail: str


class WSEvent(BaseModel):
    tag: Literal["RUN", "OK", "WARN", "ERR", "DONE"]
    module: str
    message: str = ""
    data: dict | None = None


class ReconReport(BaseModel):
    target: str
    target_type: str
    risk_level: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    findings: list[Finding]
    modules: dict
    timestamp: datetime
