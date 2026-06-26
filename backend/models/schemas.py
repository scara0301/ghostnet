from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, field_validator, model_validator

# --- target validation -------------------------------------------------------
# GHOSTNET performs *active* recon (the rep module port-scans the target via
# HackerTarget), so an unvalidated target turns the server into an open relay
# that scans arbitrary hosts on its own IP. We constrain the target tightly and
# require it to match its declared type before any module is tasked.
_MAX_TARGET_LEN = 255
# Hostname per RFC 1123 (labels 1-63 chars, no leading/trailing hyphen).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_EMAIL_RE = re.compile(r"^[^@\s]{1,64}@(?=.{1,253}$)[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
# Characters that enable path-segment / header / log injection into outbound URLs.
_FORBIDDEN = set('/\\?#%\x00') | {"\r", "\n", "\t", " "}


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class TargetRequest(BaseModel):
    target: str
    target_type: Literal["domain", "ip", "email"]

    @field_validator("target")
    @classmethod
    def _sanitize(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target must not be empty")
        if len(v) > _MAX_TARGET_LEN:
            raise ValueError("target too long")
        if any(c in v for c in _FORBIDDEN):
            raise ValueError("target contains forbidden characters")
        return v

    @model_validator(mode="after")
    def _match_type(self) -> "TargetRequest":
        t = self.target
        if self.target_type == "ip":
            try:
                ip = ipaddress.ip_address(t)
            except ValueError as exc:
                raise ValueError("invalid IP address") from exc
            # Refuse to scan non-public space (loopback/RFC1918/link-local/reserved):
            # blocks SSRF-into-internal-hosts and metadata endpoints.
            if (ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
                raise ValueError("only public IP addresses may be scanned")
        elif self.target_type == "domain":
            if _is_ip(t):
                raise ValueError("expected a domain, got an IP")
            if "." not in t or not _HOSTNAME_RE.match(t):
                raise ValueError("invalid domain name")
        elif self.target_type == "email":
            if not _EMAIL_RE.match(t):
                raise ValueError("invalid email address")
        return self


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
