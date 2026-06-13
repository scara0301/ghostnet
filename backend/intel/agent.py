"""Autonomous Intelligence Analyst — the reasoning loop, not a pipeline.

The baseline GHOSTNET runs a fixed module list. This agent instead behaves like a
junior analyst: it forms hypotheses, decides which collection to task next by
*value of information*, runs it, updates its beliefs with Bayesian odds, rejects
hypotheses the evidence kills, and -- crucially -- stops early when further
collection wouldn't change any conclusion, or escalates a "request for
collection" when a promising lead can't be resolved with the tools on hand.

Belief update is exact log-odds accumulation:

    logit(posterior) = logit(prior) + Σ  LLR(evidence_k)

Planning is greedy expected-information-gain: a module is worth running in
proportion to how much unresolved-hypothesis uncertainty it could move, divided
by its cost. Everything is deterministic and runs offline; the ``run_module``
collaborator is injected, so tests drive it with canned module output and the
production path uses the real recon modules.
"""
from __future__ import annotations

import math
from collections.abc import Awaitable, Callable

from backend.agent.orchestrator import PIPELINE
from backend.intel import bayes
from backend.intel.actor_match import match_actors
from backend.intel.adversary import simulate_attack_paths
from backend.intel.cluster import cluster_infrastructure
from backend.intel.evolution import forecast_all
from backend.intel.graph import DigitalTwin
from backend.intel.registry import MODULE_COST, default_runner
from backend.intel.relations import predict_hidden_edges
from backend.intel.schemas import (
    AgentDecision, AnalystReport, Hypothesis, PostureEstimate,
)
from backend.intel.store import SnapshotStore

RunModule = Callable[[str, str, object], Awaitable[dict]]

_CONFIRM, _REJECT = 0.75, 0.20
_STAGING_TOKENS = ("dev", "stag", "test", "qa", "uat", "preprod", "sandbox", "internal")


def _logit(p: float) -> float:
    p = min(max(p, 1e-6), 1 - 1e-6)
    return math.log(p / (1 - p))


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def _by_module(results: list[dict]) -> dict[str, dict]:
    return {r.get("module"): (r.get("data") or {}) for r in results}


# -- hypothesis library -------------------------------------------------------
# Each hypothesis declares a prior, the modules whose evidence bears on it, and
# an evaluator returning the summed log-likelihood-ratio plus human notes.

def _h_email_weak(by: dict, posture: PostureEstimate) -> tuple[float, list[str]]:
    dns = by.get("dns")
    if dns is None:
        return 0.0, []
    llr, notes = 0.0, []
    txt = " ".join(dns.get("TXT", []) or []).lower()
    raw_dmarc = dns.get("DMARC")               # dns module returns DMARC as a list
    dmarc = (" ".join(raw_dmarc) if isinstance(raw_dmarc, list) else (raw_dmarc or "")).lower()
    if "v=spf1" not in txt:
        llr += 1.2; notes.append("no SPF record")
    else:
        llr -= 1.5; notes.append("SPF present")
    if "v=dmarc1" not in dmarc:
        llr += 1.0; notes.append("no DMARC record")
    else:
        llr -= 1.2; notes.append("DMARC present")
    if not dns.get("MX"):
        llr += 0.5; notes.append("no MX")
    return llr, notes


def _h_staging(by: dict, posture: PostureEstimate) -> tuple[float, list[str]]:
    llr, notes = 0.0, []
    subs = (by.get("crt") or {}).get("subdomains", []) or []
    subs = subs + ((by.get("rep") or {}).get("hosts", []) or [])
    staging = [s for s in subs if any(t in str(s).lower() for t in _STAGING_TOKENS)]
    if staging:
        llr += min(2.5, 0.9 * len(staging)); notes.append(f"staging hosts: {staging[:3]}")
    elif "crt" in by:
        llr -= 0.5; notes.append("no staging-named hosts in CT")
    return llr, notes


def _h_shared_infra(by: dict, posture: PostureEstimate) -> tuple[float, list[str]]:
    llr, notes = 0.0, []
    subs = (by.get("crt") or {}).get("subdomains", []) or []
    if len(subs) > 5:
        llr += 0.8; notes.append(f"{len(subs)} subdomains share apex")
    geo = by.get("geo") or {}
    if geo.get("hosting"):
        llr += 0.6; notes.append("hosting/datacenter ASN")
    return llr, notes


def _h_malicious(by: dict, posture: PostureEstimate) -> tuple[float, list[str]]:
    llr, notes = 0.0, []
    otx = by.get("otx")
    if otx is not None:
        pulses = otx.get("pulse_count", otx.get("pulses", 0)) or 0
        if pulses > 0:
            llr += 2.5; notes.append(f"{pulses} OTX threat pulses")
        else:
            llr -= 1.0; notes.append("no OTX threat pulses")
    geo = by.get("geo") or {}
    if geo.get("proxy"):
        llr += 0.8; notes.append("proxy/anonymizer flag")
    return llr, notes


def _h_exploitable(by: dict, posture: PostureEstimate) -> tuple[float, list[str]]:
    llr, notes = 0.0, []
    rep = by.get("rep")
    if rep is not None:
        ports = rep.get("open_ports", rep.get("ports", [])) or []
        danger = [p for p in ports if p in (21, 22, 23, 25, 445, 3389, 5900, 6379, 27017, 3306)]
        if danger:
            llr += min(3.0, 1.2 * len(danger)); notes.append(f"exposed services: {danger}")
        else:
            llr -= 0.8; notes.append("no dangerous ports observed")
    return llr, notes


def _h_expiry_risk(by: dict, posture: PostureEstimate) -> tuple[float, list[str]]:
    whois = by.get("whois")
    if whois is None:
        return 0.0, []
    llr, notes = 0.0, []
    days = whois.get("days_until_expiry")
    if isinstance(days, (int, float)):
        if days < 30:
            llr += 2.2; notes.append(f"expires in {days}d")
        elif days < 90:
            llr += 0.6; notes.append(f"expires in {days}d")
        else:
            llr -= 1.0; notes.append(f"{days}d to expiry")
    status = " ".join(whois.get("status") or []).lower()
    if status and "prohibited" not in status:
        llr += 0.8; notes.append("no registrar transfer/delete lock")
    return llr, notes


_HYPOTHESES = [
    ("H1", "Target has weak email security posture", 0.30, ["dns", "email"], _h_email_weak),
    ("H2", "Target exposes staging/dev infrastructure", 0.20, ["crt", "rep"], _h_staging),
    ("H3", "Target shares infrastructure across many assets", 0.25, ["crt", "geo"], _h_shared_infra),
    ("H4", "Target resembles malicious/phishing infrastructure", 0.10, ["otx", "geo"], _h_malicious),
    ("H5", "Target exposes externally exploitable services", 0.15, ["rep", "geo"], _h_exploitable),
    ("H6", "Domain at risk of expiry/takeover", 0.15, ["whois"], _h_expiry_risk),
]


def _seed(target_type: str):
    pipeline = set(PIPELINE.get(target_type, []))
    return [h for h in _HYPOTHESES if set(h[3]) & pipeline]


def _evaluate(spec, by, posture, ran: set[str], pipeline: set[str]) -> Hypothesis:
    hid, statement, prior, relevant, fn = spec
    llr, notes = fn(by, posture)
    posterior = _sigmoid(_logit(prior) + llr)
    untested = [m for m in relevant if m in pipeline and m not in ran]
    # Confirm early if the evidence is already strong; otherwise keep collecting
    # while relevant evidence remains. Crucially, never *reject* a hypothesis that
    # still has untested collection -- you cannot reject what you never checked
    # (this is what stops a low-prior hypothesis from dying before its module runs).
    if posterior >= _CONFIRM:
        status = "confirmed"
    elif untested:
        status = "needs_evidence"
    elif posterior <= _REJECT:
        status = "rejected"
    else:
        status = "open"
    return Hypothesis(id=hid, statement=statement, prior=prior,
                      posterior=round(posterior, 4), status=status,
                      evidence=notes, needs=untested)


def _voi(module: str, hyps: list[Hypothesis], specs) -> float:
    """Greedy value of information: how much live uncertainty this module touches."""
    relevant_by_id = {s[0]: set(s[3]) for s in specs}
    value = 0.0
    for h in hyps:
        if h.status in ("confirmed", "rejected"):
            continue
        if module in relevant_by_id.get(h.id, ()):
            uncertainty = 1.0 - abs(2 * h.posterior - 1.0)   # peaks at p=0.5
            value += uncertainty
    return value / MODULE_COST.get(module, 1.0)


async def run_analysis(
    target: str,
    target_type: str,
    *,
    run_module: RunModule | None = None,
    client=None,
    budget: float = 10.0,
    min_voi: float = 0.05,
    store: SnapshotStore | None = None,
    horizon_days: int = 30,
) -> AnalystReport:
    run_module = run_module or default_runner
    pipeline = set(PIPELINE.get(target_type, []))
    specs = _seed(target_type)

    twin = DigitalTwin()
    results: list[dict] = []
    ran: set[str] = set()
    decisions: list[AgentDecision] = []
    spent, step = 0.0, 0

    def current_posture() -> PostureEstimate:
        return bayes.infer_posture(target, bayes.observe_controls(results))

    hyps = [_evaluate(s, {}, current_posture(), ran, pipeline) for s in specs]

    while spent < budget:
        candidates = [m for m in pipeline if m not in ran]
        # Only consider modules we can still afford; spend remaining budget on the
        # best affordable option rather than stalling on an unaffordable favourite.
        affordable = [m for m in candidates if spent + MODULE_COST.get(m, 1.0) <= budget]
        if not affordable:
            break
        scored = sorted(affordable, key=lambda m: _voi(m, hyps, specs), reverse=True)
        best = scored[0]
        best_voi = _voi(best, hyps, specs)

        # Stop early if nothing left is worth its cost (analyst judgement: "enough").
        if best_voi < min_voi and step > 0:
            decisions.append(AgentDecision(
                step=step, action="stop", expected_value=round(best_voi, 4),
                reason="marginal evidence value below threshold; conclusions stable",
            ))
            break

        step += 1
        decisions.append(AgentDecision(
            step=step, action="run_module", module=best,
            expected_value=round(best_voi, 4),
            reason=f"highest expected information gain among {sorted(candidates)}",
        ))
        try:
            result = await run_module(best, target, client)
        except Exception as exc:                      # collection failures never crash the analyst
            result = {"module": best, "data": {}, "findings": [], "error": str(exc)}
        results.append(result)
        ran.add(best)
        spent += MODULE_COST.get(best, 1.0)
        twin.ingest_module(target, result)
        posture = current_posture()
        hyps = [_evaluate(s, _by_module(results), posture, ran, pipeline) for s in specs]

    posture = current_posture()

    # Temporal intelligence: persist this snapshot, then forecast from history.
    forecasts = []
    if store is not None:
        try:
            findings_count = sum(len(r.get("findings", []) or []) for r in results)
            store.save(target, twin, posture=posture.theta_mean, findings=findings_count)
            forecasts = forecast_all(target, store.history(target), horizon_days)
        except Exception:
            forecasts = []

    # Unresolved-but-promising hypotheses with nothing left to run -> escalate.
    for h in hyps:
        if h.status in ("open", "needs_evidence") and 0.35 <= h.posterior <= 0.65:
            step += 1
            decisions.append(AgentDecision(
                step=step, action="request_collection", module=None,
                expected_value=round(h.posterior, 3),
                reason=f"{h.id} unresolved (p={h.posterior}); request external collection "
                       f"(passive DNS / active scan) for: {h.statement}",
            ))

    return AnalystReport(
        target=target, target_type=target_type, decisions=decisions, hypotheses=hyps,
        posture=posture, clusters=cluster_infrastructure(twin),
        forecasts=forecasts, attack_paths=simulate_attack_paths(twin),
        actor_matches=match_actors(twin), predicted_edges=predict_hidden_edges(twin),
        modules_run=sorted(ran), modules_skipped=sorted(pipeline - ran),
    )
