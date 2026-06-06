"""Risk engine tests — scoring ladder and report aggregation robustness."""
from __future__ import annotations

from datetime import datetime

from backend.agent.risk_engine import build_report, score
from backend.models.schemas import Finding, ReconReport


def _f(sev: str) -> Finding:
    return Finding(severity=sev, title=f"{sev} finding", detail="d")


class TestScore:
    def test_empty_is_low(self):
        assert score([]) == "LOW"

    def test_critical_takes_precedence(self):
        assert score([_f("CRITICAL"), _f("HIGH"), _f("MEDIUM")]) == "CRITICAL"

    def test_single_high_is_high(self):
        # Regression: a lone HIGH previously fell through to LOW.
        assert score([_f("HIGH")]) == "HIGH"

    def test_multiple_high_is_high(self):
        assert score([_f("HIGH"), _f("HIGH")]) == "HIGH"

    def test_medium_is_medium(self):
        assert score([_f("MEDIUM")]) == "MEDIUM"

    def test_low_only_is_low(self):
        assert score([_f("LOW"), _f("LOW")]) == "LOW"

    def test_info_only_is_low(self):
        assert score([_f("INFO"), _f("INFO")]) == "LOW"

    def test_high_outranks_medium(self):
        assert score([_f("MEDIUM"), _f("HIGH")]) == "HIGH"


class TestBuildReport:
    def test_aggregates_findings_across_modules(self):
        results = [
            {"module": "dns", "data": {"A": []}, "findings": [{"severity": "MEDIUM", "title": "t", "detail": "d"}]},
            {"module": "otx", "data": {}, "findings": [{"severity": "CRITICAL", "title": "t", "detail": "d"}]},
        ]
        report = build_report("example.com", "domain", results)
        assert isinstance(report, ReconReport)
        assert len(report.findings) == 2
        assert report.risk_level == "CRITICAL"
        assert isinstance(report.timestamp, datetime)

    def test_module_data_preserved_in_map(self):
        results = [{"module": "dns", "data": {"A": ["1.2.3.4"]}, "findings": []}]
        report = build_report("example.com", "domain", results)
        assert report.modules["dns"]["data"] == {"A": ["1.2.3.4"]}
        assert report.modules["dns"]["findings"] == []

    def test_invalid_findings_skipped_not_raised(self):
        results = [{
            "module": "broken",
            "data": {},
            "findings": [
                {"severity": "NOPE", "title": "bad sev", "detail": "d"},  # invalid severity
                {"title": "missing severity"},                             # missing fields
                {"severity": "HIGH", "title": "good", "detail": "ok"},     # valid
            ],
        }]
        report = build_report("example.com", "domain", results)
        assert len(report.findings) == 1
        assert report.findings[0].title == "good"
        assert report.risk_level == "HIGH"

    def test_passes_through_finding_objects(self):
        results = [{"module": "dns", "data": {}, "findings": [Finding(severity="LOW", title="t", detail="d")]}]
        report = build_report("example.com", "domain", results)
        assert len(report.findings) == 1
        assert report.findings[0].severity == "LOW"

    def test_missing_module_key_defaults_to_unknown(self):
        results = [{"data": {}, "findings": []}]
        report = build_report("example.com", "domain", results)
        assert "unknown" in report.modules

    def test_empty_pipeline_is_low(self):
        report = build_report("example.com", "domain", [])
        assert report.risk_level == "LOW"
        assert report.findings == []
