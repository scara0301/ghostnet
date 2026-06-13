"""GHOSTNET intelligence layer.

Sits above the recon modules and turns raw observations into *new* intelligence:
a continuously-updated Digital Twin, Bayesian recon-gap discovery, infrastructure
clustering, threat-evolution forecasting, adversarial path simulation, behavioural
threat-actor matching, hidden-relationship prediction, and an autonomous analyst
that decides what to collect and which hypotheses survive.
"""
from __future__ import annotations

from backend.intel.agent import run_analysis
from backend.intel.bayes import infer_posture, observe_controls
from backend.intel.graph import DigitalTwin
from backend.intel.schemas import AnalystReport

__all__ = [
    "run_analysis",
    "infer_posture",
    "observe_controls",
    "DigitalTwin",
    "AnalystReport",
]
