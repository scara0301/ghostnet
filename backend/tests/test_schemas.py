"""Pydantic schema validation tests — the WebSocket boundary contract."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.models.schemas import Finding, ReconReport, TargetRequest, WSEvent


class TestTargetRequest:
    @pytest.mark.parametrize("target,ttype", [
        ("example.com", "domain"),
        ("scanme.nmap.org", "domain"),
        ("8.8.8.8", "ip"),
        ("2606:4700:4700::1111", "ip"),
        ("admin@example.com", "email"),
    ])
    def test_valid_type_matched_targets(self, target, ttype):
        req = TargetRequest(target=target, target_type=ttype)
        assert req.target == target and req.target_type == ttype

    def test_invalid_target_type_rejected(self):
        with pytest.raises(ValidationError):
            TargetRequest(target="example.com", target_type="subnet")

    def test_target_required(self):
        with pytest.raises(ValidationError):
            TargetRequest(target_type="domain")

    # --- hardening: target must match its declared type ---------------------
    @pytest.mark.parametrize("target,ttype", [
        ("example.com", "ip"),        # not an IP
        ("example.com", "email"),     # not an email
        ("8.8.8.8", "domain"),        # IP passed as domain
        ("not an email", "email"),
        ("nodothostname", "domain"),  # single label, no dot
    ])
    def test_type_mismatch_rejected(self, target, ttype):
        with pytest.raises(ValidationError):
            TargetRequest(target=target, target_type=ttype)

    @pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1",
                                     "169.254.1.1", "::1", "0.0.0.0"])
    def test_non_public_ip_rejected(self, ip):
        # Blocks SSRF-into-internal-hosts and metadata endpoints.
        with pytest.raises(ValidationError):
            TargetRequest(target=ip, target_type="ip")

    @pytest.mark.parametrize("target", [
        "example.com/../admin",       # path-segment injection
        "example.com?q=1",
        "example.com#frag",
        "evil.com\r\nHost: x",        # CRLF injection
        "a b.com",                    # internal whitespace
        "",                           # empty
        "x" * 300,                    # over length cap
    ])
    def test_malicious_or_malformed_target_rejected(self, target):
        with pytest.raises(ValidationError):
            TargetRequest(target=target, target_type="domain")

    def test_target_is_stripped(self):
        req = TargetRequest(target="  example.com  ", target_type="domain")
        assert req.target == "example.com"


class TestFinding:
    @pytest.mark.parametrize("sev", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
    def test_valid_severities(self, sev):
        f = Finding(severity=sev, title="t", detail="d")
        assert f.severity == sev

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            Finding(severity="SEVERE", title="t", detail="d")

    def test_missing_fields_rejected(self):
        with pytest.raises(ValidationError):
            Finding(severity="LOW")


class TestWSEvent:
    @pytest.mark.parametrize("tag", ["RUN", "OK", "WARN", "ERR", "DONE"])
    def test_valid_tags(self, tag):
        ev = WSEvent(tag=tag, module="dns")
        assert ev.tag == tag

    def test_defaults(self):
        ev = WSEvent(tag="OK", module="dns")
        assert ev.message == ""
        assert ev.data is None

    def test_invalid_tag_rejected(self):
        with pytest.raises(ValidationError):
            WSEvent(tag="FATAL", module="dns")

    def test_serializes_to_json(self):
        ev = WSEvent(tag="WARN", module="dns", message="x", data={"k": "v"})
        assert '"tag":"WARN"' in ev.model_dump_json()


class TestReconReport:
    def _report(self, **kwargs):
        defaults = dict(
            target="example.com",
            target_type="domain",
            risk_level="LOW",
            findings=[],
            modules={},
            timestamp=datetime.now(timezone.utc),
        )
        defaults.update(kwargs)
        return ReconReport(**defaults)

    def test_valid_report(self):
        report = self._report(risk_level="CRITICAL")
        assert report.risk_level == "CRITICAL"

    def test_info_not_allowed_as_risk_level(self):
        # Finding allows INFO, but aggregate risk only spans CRITICAL..LOW.
        with pytest.raises(ValidationError):
            self._report(risk_level="INFO")

    def test_findings_coerced_to_models(self):
        report = self._report(findings=[Finding(severity="HIGH", title="t", detail="d")])
        assert isinstance(report.findings[0], Finding)
