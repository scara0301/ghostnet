"""Autonomous analyst loop — the behaviour that makes GHOSTNET an *analyst*.

We inject a deterministic ``run_module`` so the test exercises the reasoning
(planning, Bayesian updates, hypothesis lifecycle, early-stop, escalation)
without any network. The canned evidence is designed so that:
  * H1 (weak email) -> confirmed   (no SPF/DMARC/MX)
  * H4 (malicious)  -> rejected     (no OTX pulses)
  * H5 (exploitable)-> rejected     (no open ports)
  * H2 (staging)    -> unresolved    (one dev host) -> escalation
  * whois has zero value-of-information -> skipped
"""
from __future__ import annotations

from backend.intel.agent import run_analysis

_CANNED = {
    "dns": {"module": "dns", "data": {"A": ["1.2.3.4"], "MX": [], "TXT": [], "DMARC": ""}, "findings": []},
    "crt": {"module": "crt", "data": {"subdomains": ["www.x.com", "dev.x.com"]}, "findings": []},
    "geo": {"module": "geo", "data": {"query": "1.2.3.4", "hosting": False, "proxy": False}, "findings": []},
    "otx": {"module": "otx", "data": {"pulse_count": 0}, "findings": []},
    "rep": {"module": "rep", "data": {"open_ports": []}, "findings": []},
    "whois": {"module": "whois", "data": {"status": ["clientDeleteProhibited"]}, "findings": []},
}


async def _fake_runner(name, target, client):
    return _CANNED[name]


def _hyp(report, hid):
    return next(h for h in report.hypotheses if h.id == hid)


async def test_agent_runs_and_resolves_hypotheses():
    report = await run_analysis("x.com", "domain", run_module=_fake_runner)
    assert report.modules_run, "agent should have run at least one module"
    assert set(report.modules_run) <= {"whois", "dns", "crt", "geo", "otx", "rep"}
    assert _hyp(report, "H1").status == "confirmed"
    assert _hyp(report, "H4").status == "rejected"
    assert _hyp(report, "H5").status == "rejected"


async def test_agent_plans_by_value_of_information():
    report = await run_analysis("x.com", "domain", run_module=_fake_runner)
    first = next(d for d in report.decisions if d.action == "run_module")
    # geo / dns carry the highest initial information value; whois carries none.
    assert first.module in ("geo", "dns")
    assert "whois" in report.modules_skipped


async def test_agent_stops_early_and_escalates():
    report = await run_analysis("x.com", "domain", run_module=_fake_runner)
    actions = [d.action for d in report.decisions]
    assert "stop" in actions                       # judged further collection not worth it
    assert "request_collection" in actions         # H2 left unresolved -> tasks more intel


async def test_agent_survives_module_failure():
    async def flaky(name, target, client):
        if name == "otx":
            raise RuntimeError("otx down")
        return _CANNED[name]

    report = await run_analysis("x.com", "domain", run_module=flaky)
    assert report.modules_run                       # did not crash
    assert _hyp(report, "H1").status == "confirmed"


async def test_ip_target_pipeline_subset():
    report = await run_analysis("8.8.8.8", "ip", run_module=_fake_runner)
    assert set(report.modules_run) <= {"geo", "otx", "rep"}
    # email/dns-only hypotheses are not even seeded for an IP target.
    assert all(h.id != "H1" for h in report.hypotheses)
