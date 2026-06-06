"""Pydantic schema validation tests — the WebSocket boundary contract."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from backend.models.schemas import Finding, ReconReport, TargetRequest, WSEvent


class TestTargetRequest:
    @pytest.mark.parametrize("ttype", ["domain", "ip", "email"])
    def test_valid_target_types(self, ttype):
        req = TargetRequest(target="example.com", target_type=ttype)
        assert req.target_type == ttype

    def test_invalid_target_type_rejected(self):
        with pytest.raises(ValidationError):
            TargetRequest(target="example.com", target_type="subnet")

    def test_target_required(self):
        with pytest.raises(ValidationError):
            TargetRequest(target_type="domain")


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
