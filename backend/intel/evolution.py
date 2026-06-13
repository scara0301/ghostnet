"""Threat Evolution Engine — forecast the future attack surface from history.

Given a time-ordered list of twin snapshots for one target, we fit closed-form
temporal models (no training, no GPU) and project them forward:

  * subdomain emergence  -- homogeneous Poisson process on observed arrivals;
                            P(>=1 new in horizon) = 1 - e^(-lambda * h)
  * domain expiry        -- logistic lapse hazard on days-to-expiry, shifted by
                            the org's historical renewal lead time
  * cert anomaly         -- robust z-score (median / MAD) on issuance cadence;
                            off-cadence or new-issuer certs flag possible
                            mis-issuance or phishing-cert staging
  * infra migration      -- set diff of resolving IPs / ASNs between snapshots

These are deliberately interpretable estimators. A Temporal Point Process /
Temporal Transformer upgrade is specified in the architecture doc and slots in
behind the same ``forecast_*`` signatures.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone

from backend.intel.graph import DigitalTwin
from backend.intel.schemas import Forecast


def _subdomains(twin: DigitalTwin) -> set[str]:
    return {n.id for n in twin.of_type("subdomain")}


def _ips(twin: DigitalTwin) -> set[str]:
    return {n.id for n in twin.of_type("ip")}


def _asns(twin: DigitalTwin) -> set[str]:
    return {n.id for n in twin.of_type("asn")}


def forecast_subdomain_emergence(history: list[dict], horizon_days: int = 30) -> Forecast:
    """Poisson arrival-rate estimate from new subdomains across snapshots."""
    if len(history) < 2:
        return Forecast(kind="subdomain_emergence", horizon_days=horizon_days,
                        probability=0.0, confidence=0.2,
                        detail="insufficient history (need >=2 snapshots)")
    arrivals = 0
    span_days = 0.0
    prev = history[0]
    for cur in history[1:]:
        new = _subdomains(cur["twin"]) - _subdomains(prev["twin"])
        arrivals += len(new)
        span_days += max((cur["ts"] - prev["ts"]).total_seconds() / 86400.0, 1e-6)
        prev = cur
    lam = arrivals / span_days if span_days else 0.0          # per day
    p = 1.0 - math.exp(-lam * horizon_days)
    conf = min(0.9, 0.3 + 0.1 * (len(history) - 1))
    return Forecast(
        kind="subdomain_emergence", horizon_days=horizon_days,
        probability=round(p, 4), expected_count=round(lam * horizon_days, 3),
        confidence=round(conf, 3),
        detail=f"lambda={lam:.4f}/day over {span_days:.1f}d; {arrivals} historical arrivals",
    )


def forecast_domain_expiry(expiry: datetime, now: datetime | None = None,
                           renewal_lead_days: float = 30.0,
                           horizon_days: int = 30) -> Forecast:
    """Logistic lapse hazard centred on the org's renewal lead time."""
    now = now or datetime.now(timezone.utc)
    days_left = (expiry - now).total_seconds() / 86400.0
    # Lapse probability rises as days_left drops below the renewal lead time.
    x = (renewal_lead_days - days_left) / max(renewal_lead_days, 1.0)
    p_lapse = 1.0 / (1.0 + math.exp(-3.0 * x))
    if days_left < 0:
        p_lapse = max(p_lapse, 0.97)
    return Forecast(
        kind="domain_expiry", horizon_days=horizon_days,
        probability=round(p_lapse, 4), expected_count=round(days_left, 1),
        confidence=0.7,
        detail=f"{days_left:.0f}d to expiry; lapse risk vs {renewal_lead_days:.0f}d renewal lead",
    )


def detect_cert_anomaly(issuance_days: list[float], new_issuer: bool = False,
                        horizon_days: int = 30) -> Forecast:
    """Robust outlier test on inter-issuance gaps (median/MAD z-score)."""
    if len(issuance_days) < 3:
        base = 0.4 if new_issuer else 0.1
        return Forecast(kind="cert_anomaly", horizon_days=horizon_days,
                        probability=base, confidence=0.3,
                        detail="insufficient cert cadence history")
    gaps = [issuance_days[i + 1] - issuance_days[i] for i in range(len(issuance_days) - 1)]
    s = sorted(gaps)
    median = s[len(s) // 2]
    mad = sorted(abs(g - median) for g in gaps)[len(gaps) // 2] or 1.0
    latest = gaps[-1]
    z = abs(latest - median) / (1.4826 * mad)
    p = 1.0 - math.exp(-0.5 * z)                 # bigger z -> closer to 1
    if new_issuer:                               # a new CA is a strong standalone signal
        p = min(1.0, p + 0.4)
    detail = f"latest gap {latest:.1f}d vs median {median:.1f}d (z={z:.2f})"
    if new_issuer:
        detail += "; new CA issuer observed"
    return Forecast(kind="cert_anomaly", horizon_days=horizon_days,
                    probability=round(p, 4), confidence=0.6, detail=detail)


def detect_migration(history: list[dict], horizon_days: int = 30) -> Forecast:
    """Detect infrastructure migration between the two most recent snapshots."""
    if len(history) < 2:
        return Forecast(kind="infra_migration", horizon_days=horizon_days,
                        probability=0.0, confidence=0.2, detail="insufficient history")
    prev, cur = history[-2], history[-1]
    ip_changed = _ips(cur["twin"]) ^ _ips(prev["twin"])
    asn_changed = _asns(cur["twin"]) ^ _asns(prev["twin"])
    moved = len(ip_changed) + 2 * len(asn_changed)
    p = 1.0 - math.exp(-0.4 * moved)
    detail = f"{len(ip_changed)} IP delta, {len(asn_changed)} ASN delta"
    return Forecast(kind="infra_migration", horizon_days=horizon_days,
                    probability=round(p, 4), confidence=0.6, detail=detail)


def forecast_all(target: str, history: list[dict], horizon_days: int = 30) -> list[Forecast]:
    out = [
        forecast_subdomain_emergence(history, horizon_days),
        detect_migration(history, horizon_days),
    ]
    latest = history[-1]["twin"] if history else None
    if latest is not None:
        for node in latest.of_type("domain"):
            exp = node.attrs.get("expiry")
            if exp:
                try:
                    out.append(forecast_domain_expiry(datetime.fromisoformat(exp),
                                                      horizon_days=horizon_days))
                except (ValueError, TypeError):
                    pass
    return out
