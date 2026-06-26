"""Intelligence-layer data contracts.

These models sit *above* the recon modules. Where ``backend.models.schemas``
describes what crosses the WebSocket boundary, these describe the entities,
beliefs, forecasts and inferences the autonomous analyst reasons over.

Everything here is pure Pydantic v2 + stdlib so the intelligence engines stay
offline-testable through the same ``httpx.MockTransport`` harness as the modules.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

# Entities that can appear in the Digital Twin graph.
EntityType = Literal[
    "domain", "subdomain", "ip", "netblock", "asn", "cert", "nameserver",
    "mx", "org", "tech", "email", "breach", "cloud_asset", "internet",
]

# Typed relationships between entities. ``predicted`` edges are *inferred*,
# never observed, and always carry sub-1.0 confidence.
RelType = Literal[
    "resolves_to", "subdomain_of", "hosted_on", "announced_by",
    "presents_cert", "shares_cert", "uses_ns", "mx_for", "same_registrar",
    "runs_tech", "owned_by", "breached_in", "sibling_of", "migrated_from",
    "reachable_from", "predicted",
]


def now() -> datetime:
    return datetime.now(timezone.utc)


class Node(BaseModel):
    id: str
    type: EntityType
    label: str = ""
    attrs: dict = Field(default_factory=dict)
    confidence: float = 1.0
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)


class Edge(BaseModel):
    src: str
    dst: str
    type: RelType
    confidence: float = 1.0
    attrs: dict = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=now)
    last_seen: datetime = Field(default_factory=now)


# ---- Recon Gap Discovery (Bayesian latent-trait model) ----------------------

class ControlEstimate(BaseModel):
    control: str
    observed: bool | None                 # True=present, False=absent, None=unknown
    expected_presence: float              # posterior E[P(present | posture)]
    gap_confidence: float                 # how anomalous the absence is
    severity: Severity
    rationale: str


class PostureEstimate(BaseModel):
    target: str
    theta_mean: float                     # latent security-maturity posterior mean
    theta_std: float
    controls: list[ControlEstimate] = Field(default_factory=list)

    def gaps(self) -> list[ControlEstimate]:
        return [c for c in self.controls if c.observed is False and c.severity != "INFO"]


# ---- Infrastructure clustering ---------------------------------------------

ClusterLabel = Literal["active", "staging", "abandoned", "unknown"]


class Cluster(BaseModel):
    id: str
    members: list[str] = Field(default_factory=list)
    label: ClusterLabel = "unknown"
    confidence: float = 0.0
    evidence: list[str] = Field(default_factory=list)


# ---- Threat evolution / forecasting ----------------------------------------

ForecastKind = Literal[
    "subdomain_emergence", "domain_expiry", "cert_anomaly",
    "infra_migration", "phishing_campaign",
]


class Forecast(BaseModel):
    kind: ForecastKind
    horizon_days: int
    probability: float
    expected_count: float = 0.0
    confidence: float = 0.5
    detail: str = ""


# ---- Adversarial simulation -------------------------------------------------

class AttackStep(BaseModel):
    src: str
    dst: str
    technique: str
    confidence: float
    rationale: str


class AttackPath(BaseModel):
    entry: str
    objective: str
    steps: list[AttackStep] = Field(default_factory=list)
    path_confidence: float = 0.0          # product of step confidences
    impact: Severity = "MEDIUM"
    rationale: str = ""


# ---- Threat-actor matching --------------------------------------------------

class ActorMatch(BaseModel):
    actor: str
    score: float
    matched_features: list[str] = Field(default_factory=list)
    rationale: str = ""


# ---- Autonomous analyst loop ------------------------------------------------

HypothesisStatus = Literal["open", "needs_evidence", "confirmed", "rejected"]


class Hypothesis(BaseModel):
    id: str
    statement: str
    prior: float
    posterior: float
    status: HypothesisStatus = "open"
    evidence: list[str] = Field(default_factory=list)
    needs: list[str] = Field(default_factory=list)   # modules that would test it


class AgentDecision(BaseModel):
    step: int
    action: Literal["run_module", "stop", "request_collection"]
    module: str | None = None
    reason: str = ""
    expected_value: float = 0.0


class AnalystReport(BaseModel):
    target: str
    target_type: str
    decisions: list[AgentDecision] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    posture: PostureEstimate | None = None
    clusters: list[Cluster] = Field(default_factory=list)
    forecasts: list[Forecast] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    actor_matches: list[ActorMatch] = Field(default_factory=list)
    predicted_edges: list[Edge] = Field(default_factory=list)
    graph: dict = Field(default_factory=dict)        # Digital Twin: {nodes, edges}
    modules_run: list[str] = Field(default_factory=list)
    modules_skipped: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=now)
