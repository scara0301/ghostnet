"""Recon Gap Discovery — a Bayesian latent-trait inference engine (NOT an LLM).

The question this answers is *"what information SHOULD exist but wasn't found?"*
Rule engines answer it with a fixed checklist ("missing SPF = finding"). That
produces false positives: a hobbyist parked domain is *not* expected to run
MTA-STS, so flagging its absence is noise.

We instead model a latent variable ``theta`` -- the organization's security
*maturity* -- and treat each observable control as an item in a 2-parameter
Item Response Theory (IRT) model:

    P(control_i present | theta) = sigmoid( slope * disc_i * (theta - diff_i) )

``diff_i`` is how "advanced" a control is (DNSSEC is harder than an A record);
``disc_i`` is how sharply it separates mature from immature orgs.

Inference is exact on a discretised theta grid (no sampling, fully
deterministic):

    posterior(theta) ∝ prior(theta) * Π_i  L(observation_i | theta)

A *gap* is then an absent control whose **posterior expected presence** is high:
"given how mature this target looks from everything else we observed, a control
this basic should almost certainly be here -- and it isn't." Confidence is the
posterior expectation itself. This is genuinely new intelligence: the same
missing SPF is HIGH severity for a bank-grade posture and INFO for a parked
domain, with a calibrated probability attached.
"""
from __future__ import annotations

import math

from backend.intel.schemas import ControlEstimate, PostureEstimate, Severity

# control -> (difficulty in [0,1], discrimination, impact weight, criticality)
# difficulty: how far up the maturity ladder the control sits.
# impact:     how much its absence matters when it *is* expected.
CONTROLS: dict[str, tuple[float, float, float]] = {
    # control            difficulty  disc   impact
    "a_record":          (0.05,      1.4,   0.30),
    "ct_presence":       (0.18,      1.0,   0.35),
    "tls":               (0.20,      1.6,   0.95),
    "mx":                (0.22,      1.2,   0.55),
    "spf":               (0.30,      1.5,   0.80),
    "registrar_lock":    (0.42,      1.0,   0.55),
    "dmarc":             (0.48,      1.4,   0.80),
    "dkim":              (0.52,      1.1,   0.60),
    "hsts":              (0.56,      1.1,   0.50),
    "caa":               (0.62,      1.0,   0.45),
    "dnssec":            (0.70,      1.2,   0.55),
    "dmarc_enforced":    (0.72,      1.3,   0.70),
    "mta_sts":           (0.80,      1.1,   0.45),
    "bimi":              (0.86,      0.9,   0.30),
}

_SLOPE = 6.0
_GRID = [i / 100.0 for i in range(101)]            # theta in [0, 1], 101 points
# Weak Beta(1.6, 1.6) prior: mild shrinkage toward the middle, no strong opinion.
_PRIOR = [(t ** 0.6) * ((1 - t) ** 0.6) for t in _GRID]
_PRIOR = [p / sum(_PRIOR) for p in _PRIOR]


def _p_present(theta: float, diff: float, disc: float) -> float:
    return 1.0 / (1.0 + math.exp(-_SLOPE * disc * (theta - diff)))


def _severity(expected: float, impact: float) -> Severity:
    score = expected * impact
    if score >= 0.70:
        return "CRITICAL" if impact >= 0.9 else "HIGH"
    if score >= 0.45:
        return "HIGH" if impact >= 0.9 else "MEDIUM"
    if score >= 0.25:
        return "MEDIUM" if impact >= 0.8 else "LOW"
    if score >= 0.12:
        return "LOW"
    return "INFO"


def infer_posture(target: str, observations: dict[str, bool | None]) -> PostureEstimate:
    """Grid Bayesian inference over latent maturity, then rank absent controls.

    ``observations`` maps control name -> True (present) / False (absent) /
    None or missing (unknown). Unknown controls contribute no likelihood but are
    still scored as "collection gaps".
    """
    # Posterior over theta given the observed (present/absent) controls.
    post = list(_PRIOR)
    for name, obs in observations.items():
        if obs is None or name not in CONTROLS:
            continue
        diff, disc, _ = CONTROLS[name]
        for i, t in enumerate(_GRID):
            p = _p_present(t, diff, disc)
            post[i] *= p if obs else (1.0 - p)
    total = sum(post) or 1.0
    post = [p / total for p in post]

    theta_mean = sum(t * p for t, p in zip(_GRID, post))
    theta_var = sum((t - theta_mean) ** 2 * p for t, p in zip(_GRID, post))
    theta_std = math.sqrt(max(theta_var, 0.0))

    controls: list[ControlEstimate] = []
    for name, (diff, disc, impact) in CONTROLS.items():
        obs = observations.get(name)
        expected = sum(_p_present(t, diff, disc) * p for t, p in zip(_GRID, post))
        if obs is False:
            sev = _severity(expected, impact)
            rationale = (
                f"posture theta={theta_mean:.2f}: a target this mature presents "
                f"'{name}' with p={expected:.2f}, but it is absent"
            )
            gap_conf = expected
        elif obs is None:
            sev = "INFO"
            rationale = f"'{name}' not collected; predicted presence p={expected:.2f}"
            gap_conf = expected * 0.5
        else:
            sev = "INFO"
            rationale = f"'{name}' present, consistent with theta={theta_mean:.2f}"
            gap_conf = 0.0
        controls.append(ControlEstimate(
            control=name, observed=obs, expected_presence=round(expected, 4),
            gap_confidence=round(gap_conf, 4), severity=sev, rationale=rationale,
        ))

    controls.sort(key=lambda c: c.gap_confidence, reverse=True)
    return PostureEstimate(
        target=target, theta_mean=round(theta_mean, 4),
        theta_std=round(theta_std, 4), controls=controls,
    )


def observe_controls(module_results: list[dict]) -> dict[str, bool | None]:
    """Translate raw recon module output into IRT observations.

    Absence is only asserted (``False``) when a module *successfully ran* and the
    control was genuinely not seen -- never on a hard module error, which would
    fabricate gaps. Unknown stays ``None`` so the engine reasons about collection
    gaps separately.
    """
    obs: dict[str, bool | None] = {k: None for k in CONTROLS}
    by_module = {r.get("module"): (r.get("data") or {}) for r in module_results}

    dns = by_module.get("dns")
    if dns is not None:
        # Only assert a control when the module genuinely probed it (key present);
        # otherwise leave it unknown so we never fabricate a "missing" gap.
        if "A" in dns:
            obs["a_record"] = bool(dns.get("A"))
        if "MX" in dns:
            obs["mx"] = bool(dns.get("MX"))
        if "TXT" in dns:
            txt = " ".join(dns.get("TXT") or []).lower()
            obs["spf"] = "v=spf1" in txt
        if "DMARC" in dns:
            raw = dns.get("DMARC")            # dns module returns DMARC as a list
            dmarc = (" ".join(raw) if isinstance(raw, list) else (raw or "")).lower()
            obs["dmarc"] = "v=dmarc1" in dmarc
            obs["dmarc_enforced"] = "p=quarantine" in dmarc or "p=reject" in dmarc
        for key, control in (("DKIM", "dkim"), ("DNSSEC", "dnssec"), ("CAA", "caa"),
                             ("MTA_STS", "mta_sts"), ("BIMI", "bimi")):
            if key in dns:
                obs[control] = bool(dns.get(key))

    crt = by_module.get("crt")
    if crt is not None:
        has_ct = bool(crt.get("subdomains")) or bool(crt.get("count"))
        obs["ct_presence"] = has_ct
        if has_ct:                       # CT issuance is positive evidence of TLS
            obs["tls"] = True

    whois = by_module.get("whois")
    if whois is not None and "status" in whois:
        status = " ".join(whois.get("status") or []).lower()
        obs["registrar_lock"] = "prohibited" in status

    return obs
