"""Bayesian recon-gap engine: the latent-trait inference must be *context aware*.

The headline behaviour: the SAME missing control is a real gap for a mature
target and a non-event for an immature one, because the posterior over latent
maturity differs. These tests pin that property down.
"""
from __future__ import annotations

from backend.intel.bayes import CONTROLS, infer_posture, observe_controls

_MATURE = {
    "a_record": True, "mx": True, "tls": True, "dkim": True, "hsts": True,
    "caa": True, "dnssec": True, "dmarc": True, "dmarc_enforced": True,
    "mta_sts": True, "spf": False,            # the one anomalous absence
}
_IMMATURE = {
    "a_record": True, "mx": False, "spf": False, "dmarc": False, "tls": False,
    "dnssec": False, "mta_sts": False, "caa": False, "hsts": False, "dkim": False,
}


def _control(posture, name):
    return next(c for c in posture.controls if c.control == name)


def test_posture_separates_mature_from_immature():
    mature = infer_posture("a.com", _MATURE)
    immature = infer_posture("b.com", _IMMATURE)
    assert mature.theta_mean > 0.6
    assert immature.theta_mean < 0.4
    assert mature.theta_mean > immature.theta_mean


def test_anomalous_absence_is_flagged_for_mature_target():
    mature = infer_posture("a.com", _MATURE)
    spf = _control(mature, "spf")
    assert spf.observed is False
    assert spf.expected_presence > 0.8          # a mature org "should" have SPF
    assert spf.severity in ("MEDIUM", "HIGH", "CRITICAL")
    assert spf in mature.gaps()


def test_expected_absence_is_not_a_gap_for_immature_target():
    immature = infer_posture("b.com", _IMMATURE)
    mta = _control(immature, "mta_sts")
    assert mta.observed is False
    assert mta.expected_presence < 0.2          # not expected at this maturity
    assert mta.severity == "INFO"
    assert mta not in immature.gaps()


def test_gaps_ranked_by_confidence():
    mature = infer_posture("a.com", _MATURE)
    confs = [c.gap_confidence for c in mature.controls]
    assert confs == sorted(confs, reverse=True)


def test_unknown_controls_stay_info():
    posture = infer_posture("c.com", {"a_record": True})  # everything else unknown
    spf = _control(posture, "spf")
    assert spf.observed is None
    assert spf.severity == "INFO"
    assert posture.gaps() == []


def test_observe_controls_maps_module_output():
    results = [{
        "module": "dns",
        "data": {"A": ["1.2.3.4"], "MX": [],
                 "TXT": ["v=spf1 include:_spf.google.com -all"],
                 "DMARC": "v=DMARC1; p=reject"},
    }]
    obs = observe_controls(results)
    assert obs["a_record"] is True
    assert obs["mx"] is False
    assert obs["spf"] is True
    assert obs["dmarc"] is True
    assert obs["dmarc_enforced"] is True
    assert obs["dnssec"] is None               # not observed -> unknown


def test_all_controls_present_in_estimate():
    posture = infer_posture("d.com", {})
    assert {c.control for c in posture.controls} == set(CONTROLS)
