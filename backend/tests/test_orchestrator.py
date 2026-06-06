"""Orchestrator tests — pipeline routing, event streaming, error resilience.

Modules are stubbed at the import boundary so these tests verify orchestration
logic only (sequencing, WSEvent stream shape, failure isolation) without any
network access or module-specific behaviour.
"""
from __future__ import annotations

import importlib

import pytest

from backend.agent import orchestrator
from backend.agent.orchestrator import PIPELINE, run_pipeline
from backend.models.schemas import ReconReport, WSEvent

ALL_MODULES = ("email", "whois", "dns", "crt", "geo", "otx", "rep")


async def _collect():
    events: list[WSEvent] = []

    async def send(ev: WSEvent) -> None:
        events.append(ev)

    return events, send


def _stub_module(monkeypatch, name: str, result: dict | None = None, raises: Exception | None = None):
    """Replace a module's ``run`` with a stub returning ``result`` or raising."""
    mod = importlib.import_module(f"backend.modules.{name}_module")

    async def fake_run(target, client):
        if raises is not None:
            raise raises
        return result if result is not None else {"module": name, "data": {}, "findings": []}

    monkeypatch.setattr(mod, "run", fake_run)


def _stub_all(monkeypatch, result_by_name: dict[str, dict] | None = None):
    result_by_name = result_by_name or {}
    for name in ALL_MODULES:
        _stub_module(monkeypatch, name, result_by_name.get(name))


class TestRouting:
    @pytest.mark.parametrize(
        "ttype,expected",
        [
            ("domain", ["whois", "dns", "crt", "geo", "otx", "rep"]),
            ("ip", ["geo", "otx", "rep"]),
            ("email", ["email", "whois", "dns"]),
        ],
    )
    async def test_pipeline_runs_expected_modules_in_order(self, monkeypatch, ttype, expected):
        _stub_all(monkeypatch)
        events, send = await _collect()
        await run_pipeline("example.com", ttype, send)
        run_order = [e.module for e in events if e.tag == "RUN"]
        assert run_order == expected

    async def test_unknown_target_type_is_empty_pipeline(self, monkeypatch):
        _stub_all(monkeypatch)
        events, send = await _collect()
        report = await run_pipeline("example.com", "bogus", send)
        assert [e.module for e in events if e.tag == "RUN"] == []
        assert report.risk_level == "LOW"
        # DONE must still fire.
        assert events[-1].tag == "DONE"

    def test_pipeline_constant_matches_module_map(self):
        for names in PIPELINE.values():
            for name in names:
                assert name in orchestrator._MODULE_MAP


class TestEventStreaming:
    async def test_done_event_carries_full_report(self, monkeypatch):
        _stub_all(monkeypatch, {
            "geo": {"module": "geo", "data": {"country": "US"},
                    "findings": [{"severity": "HIGH", "title": "proxy", "detail": "d"}]},
        })
        events, send = await _collect()
        report = await run_pipeline("1.1.1.1", "ip", send)

        done = events[-1]
        assert done.tag == "DONE"
        assert done.module == "engine"
        assert done.data["risk_level"] == "HIGH"
        assert isinstance(report, ReconReport)

    async def test_severity_to_tag_mapping(self, monkeypatch):
        _stub_all(monkeypatch, {
            "geo": {"module": "geo", "data": {}, "findings": [
                {"severity": "HIGH", "title": "h", "detail": "d"},
                {"severity": "MEDIUM", "title": "m", "detail": "d"},
                {"severity": "LOW", "title": "l", "detail": "d"},
                {"severity": "INFO", "title": "i", "detail": "d"},
            ]},
        })
        events, send = await _collect()
        await run_pipeline("1.1.1.1", "ip", send)

        by_title = {e.message: e.tag for e in events if e.message in ("h", "m", "l", "i")}
        assert by_title == {"h": "WARN", "m": "WARN", "l": "OK", "i": "OK"}

    async def test_each_module_emits_run_then_complete(self, monkeypatch):
        _stub_all(monkeypatch)
        events, send = await _collect()
        await run_pipeline("1.1.1.1", "ip", send)
        for name in ("geo", "otx", "rep"):
            tags = [e.tag for e in events if e.module == name]
            assert tags[0] == "RUN"
            assert "OK" in tags  # "<name> complete"


class TestErrorResilience:
    async def test_module_exception_emits_err_and_continues(self, monkeypatch):
        _stub_all(monkeypatch)
        _stub_module(monkeypatch, "geo", raises=RuntimeError("boom"))
        events, send = await _collect()
        report = await run_pipeline("1.1.1.1", "ip", send)

        err = [e for e in events if e.tag == "ERR"]
        assert any(e.module == "geo" and "boom" in e.message for e in err)
        # Pipeline still completes with the remaining modules.
        assert events[-1].tag == "DONE"
        assert isinstance(report, ReconReport)
        # otx and rep still ran after geo failed.
        assert {"otx", "rep"} <= {e.module for e in events if e.tag == "RUN"}

    async def test_malformed_finding_does_not_crash(self, monkeypatch):
        _stub_all(monkeypatch, {
            "geo": {"module": "geo", "data": {}, "findings": [{"no_severity": True}]},
        })
        events, send = await _collect()
        report = await run_pipeline("1.1.1.1", "ip", send)
        # No crash; DONE emitted; bad finding excluded from the report.
        assert events[-1].tag == "DONE"
        assert report.findings == []

    async def test_done_always_emitted_even_if_all_modules_fail(self, monkeypatch):
        for name in ("geo", "otx", "rep"):
            _stub_module(monkeypatch, name, raises=ValueError("down"))
        events, send = await _collect()
        report = await run_pipeline("1.1.1.1", "ip", send)
        assert events[-1].tag == "DONE"
        assert report.risk_level == "LOW"
