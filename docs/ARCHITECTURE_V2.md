# GHOSTNET v2 — Autonomous Intelligence Analyst

> Redesign brief: stop being a recon tool that prints API responses. Become a
> system that **produces intelligence that did not exist in any of its inputs**.

This document is implementation-grade. Everything in **§A "Shipped"** is real,
runnable, and covered by the offline test suite (`backend/tests/test_intel_*.py`,
33 tests). Everything in **§B "Specified"** is a heavyweight model design with
architecture, data, training, inference, and the exact code seam it drops into —
deliberately not faked as "working" code.

---

## 0. Thesis: why this is not an AI wrapper

A ChatGPT-over-OSINT product takes API output and rephrases it. The intelligence
content is unchanged; only the prose is new. GHOSTNET v2 inverts that:

| Input (observed) | Output (newly created intelligence) |
|---|---|
| "SPF record absent" | "This target's posture (θ=0.81) implies SPF *should* exist with p=0.97; its absence is a HIGH-confidence anomaly" — **a probability that was nowhere in the input** |
| A list of subdomains | "These 6 assets are one organization, these 2 are staging, this cluster is abandoned" — **ownership and lifecycle that no API returned** |
| Two scans a week apart | "λ=0.2 new subdomains/day → 99.7% chance of new attack surface in 30d; cert cadence z=4.1 anomaly" — **a forecast** |
| Open ports + subdomains | A confidence-scored attack graph from internet → crown jewel — **a pivot plan** |

None of these are summaries. They are inferences a language model cannot produce
because the answer is the output of a **calibrated statistical model over the
graph**, not a paraphrase of text. That is the moat (§9).

---

## 1. Layered architecture

```
                         ┌──────────────────────────────────────────────┐
   PRESENTATION          │  Live twin graph · temporal timeline · attack │
   frontend/             │  overlay · posture radar · hypothesis ledger  │
                         └───────────────▲──────────────────────────────┘
                                         │ WSEvent stream (/ws/analyst)
                         ┌───────────────┴──────────────────────────────┐
   AUTONOMY              │  Autonomous Analyst  (intel/agent.py)         │
   "junior analyst"      │  hypotheses · value-of-information planner ·  │
                         │  Bayesian belief update · escalation          │
                         └───────────────▲──────────────────────────────┘
                                         │ reads/writes
         ┌───────────────────────────────┼───────────────────────────────┐
   INFERENCE ENGINES                      │                               │
   intel/                                 │                               │
   ┌──────────────┐ ┌──────────────┐ ┌────┴─────────┐ ┌──────────────┐    │
   │ Recon-Gap    │ │ Infra        │ │ Threat       │ │ Adversarial  │    │
   │ Bayesian IRT │ │ Clustering   │ │ Evolution    │ │ Simulation   │    │
   │ bayes.py ★   │ │ cluster.py   │ │ evolution.py │ │ adversary.py │    │
   └──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘    │
   ┌──────────────┐ ┌──────────────┐                                      │
   │ Actor Match  │ │ Hidden-Edge  │   ★ = non-LLM model (deliverable #3) │
   │ actor_match  │ │ relations.py │                                      │
   └──────────────┘ └──────────────┘                                      │
                         ┌───────────────┴──────────────────────────────┐
   DIGITAL TWIN          │  DigitalTwin graph (intel/graph.py)           │
   continuously updated  │  typed nodes/edges · idempotent merge         │
                         │  SnapshotStore (intel/store.py, SQLite)       │
                         └───────────────▲──────────────────────────────┘
                                         │ ingest_module()
                         ┌───────────────┴──────────────────────────────┐
   COLLECTION            │  whois · dns · crt · geo · otx · rep · email  │
   backend/modules/      │  unchanged contract: run(target, client)->dict│
                         └──────────────────────────────────────────────┘
```

The collection layer is untouched — the v1 module contract is the ingestion API
for the twin. Everything above it is new.

---

# §A. SHIPPED (real, tested, offline)

## 2. The Digital Twin — `intel/graph.py`

A typed property graph that is the single source of truth. Not a per-scan
report: a **continuously-updated** model.

* **Nodes** (`EntityType`): domain, subdomain, ip, netblock, asn, cert,
  nameserver, mx, org, tech, email, breach, cloud_asset, internet.
* **Edges** (`RelType`): resolves_to, subdomain_of, hosted_on, announced_by,
  presents_cert, shares_cert, uses_ns, mx_for, same_registrar, owned_by,
  migrated_from, reachable_from, **predicted** (inferred, always <1.0 conf).
* **Merge is idempotent + confidence-aware**: re-ingesting a scan refreshes
  `last_seen` and takes `max(confidence)` instead of duplicating. This is the
  property that makes the twin a living model and enables temporal diffing.
* `ingest_module(target, result)` projects each recon module's
  `{module,data,findings}` into typed nodes/edges. Defensive by construction —
  never raises on partial module data.

## 3. ★ Non-LLM model #1: Bayesian Recon-Gap Engine — `intel/bayes.py`

**Problem.** "What information *should* exist but wasn't found?" Rule engines
("no SPF = finding") false-positive on parked domains that were never expected to
run advanced controls.

**Model.** A latent-trait **Item Response Theory (2-parameter logistic)** model.
A hidden variable `θ ∈ [0,1]` is the organization's security maturity. Each
control is an IRT "item":

```
P(control_i present | θ) = sigmoid( SLOPE · disc_i · (θ − diff_i) )
```

`diff_i` = how advanced the control is (A-record 0.05 … MTA-STS 0.80 … BIMI 0.86);
`disc_i` = how sharply it separates mature from immature orgs.

**Inference (exact, deterministic, no sampling).** Discretise θ on a 101-point
grid; do exact Bayesian updating:

```
posterior(θ) ∝ prior(θ) · Π_i  L(observation_i | θ)
prior(θ) = Beta(1.6, 1.6)            # weak shrinkage, no strong opinion
```

A **gap** = an *absent* control whose posterior **expected presence**
`E[P(present|θ)]` is high: "given how mature everything else makes this target
look, a control this basic should be here — and it isn't." Confidence is that
expectation; severity = `expected × impact_weight`.

**Why it's new intelligence.** The *same* missing SPF is HIGH for θ=0.81 and INFO
for θ=0.18, each with a calibrated probability. Tested in
`test_intel_bayes.py::test_anomalous_absence_is_flagged_for_mature_target` and
`::test_expected_absence_is_not_a_gap_for_immature_target`.

**Learning the parameters (production).** Difficulties/discriminations are
domain-seeded today and **fittable** from a corpus of N scanned domains by
marginal-maximum-likelihood (EM): E-step computes posterior θ per domain,
M-step refits `(disc_i, diff_i)` by logistic regression of presence on θ̂.
Data requirement: ~5k labelled domains across the maturity spectrum (cheap —
labels are the controls themselves, self-supervised).

## 4. Infrastructure Clustering — `intel/cluster.py`

Single-linkage clustering over co-ownership evidence (shared cert SANs, same /24,
same ASN, naming-token overlap) via union-find → "these assets are one org" even
across registrars/hosts. Per-asset lifecycle features then label clusters
**active / staging / abandoned** (dev/test tokens, private/cloud-internal IPs,
dangling resolution, low graph degree). Tested for grouping + staging labelling.

## 5. Threat Evolution — `intel/evolution.py`

Closed-form temporal estimators over `SnapshotStore` history:

* **Subdomain emergence**: homogeneous Poisson on observed arrivals;
  `P(≥1 new in h) = 1 − e^(−λh)`.
* **Domain-expiry lapse**: logistic hazard on days-to-expiry shifted by the org's
  renewal lead time.
* **Cert anomaly**: robust median/MAD z-score on issuance cadence; new-CA-issuer
  is a strong standalone signal (possible mis-issuance / phishing-cert staging).
* **Infra migration**: set-diff of resolving IPs/ASNs between snapshots.

Interpretable today; the Temporal-Transformer upgrade (§B.2) slots in behind the
same `forecast_*` signatures.

## 6. Adversarial Simulation — `intel/adversary.py`

Turns the passive twin into an attack graph. Each edge gets an exploitability
weight from observed signals (dangerous open ports, weak TLS, admin hostnames,
shared-cert links, breach presence). **Max-confidence path** from `internet` to
crown-jewel assets via Dijkstra over `−log(confidence)` (max-product → min-sum).
Emits `AttackPath`s with MITRE-mapped techniques and a confidence = product of
step confidences. **Simulation only — never live exploitation.**

## 7. Behavioural Threat-Actor Matching — `intel/actor_match.py`

Fingerprints *how* infrastructure is built/operated (DGA-ish naming, fresh
domains, bulletproof/datacenter ASN, LE/self-signed certs, fast-flux, port
sprawl, punycode) and scores weighted-cosine similarity vs actor profiles — so an
actor matches **even on brand-new IPs**, defeating signature rotation. Seed
profiles are illustrative; production mines them from historical campaign
clusters (DBSCAN over the same fingerprint space).

## 8. Hidden-Relationship Prediction — `intel/relations.py`

Link prediction on the twin via **Adamic–Adar** (shared-neighbour score weighting
rare links higher). Predicted edges are typed `predicted` with sub-1.0 confidence
so inferred ≠ observed. GNN upgrade in §B.1, same `predict_hidden_edges`
signature.

## 9. Autonomous Analyst — `intel/agent.py`

The behaviour that makes GHOSTNET an *analyst*, not a pipeline.

* **Belief state**: twin + module results + hypothesis ledger + budget.
* **Hypothesis library** (H1 weak-email, H2 staging-exposed, H3 shared-infra,
  H4 malicious-like, H5 exploitable). Each declares prior, the modules whose
  evidence bears on it, and an evaluator returning a **log-likelihood-ratio**.
* **Bayesian update**: `logit(posterior) = logit(prior) + Σ LLR(evidence)`.
* **Planning = value of information**: run the module that touches the most live
  hypothesis uncertainty per unit cost
  `VoI(m) = Σ_h (1−|2p_h−1|)·[m relevant] / cost(m)`. It runs `geo`/`dns` before
  `whois` and **skips whois entirely** (zero VoI) — verified in
  `test_agent_plans_by_value_of_information`.
* **Lifecycle**: confirmed (p≥.75) / rejected (p≤.20) / needs_evidence / open.
* **Early stop** when marginal VoI < ε ("enough evidence"); **escalates**
  `request_collection` for unresolved-but-promising hypotheses with nothing left
  to run — verified in `test_agent_stops_early_and_escalates`.
* Collection failures never crash the loop (`test_agent_survives_module_failure`).

Output is an `AnalystReport`: decisions + hypothesis ledger + posture + clusters +
forecasts + attack paths + actor matches + predicted edges. Streamed live over
`/ws/analyst` (`backend/main.py`, tested in `test_intel_api.py`).

---

# §B. SPECIFIED (heavyweight models — design + seam, not faked)

These are the neural upgrades. Each lists architecture, data, training,
inference, and the **exact function it replaces** so it drops in without touching
callers.

## B.1 GNN link predictor → replaces `relations.predict_hidden_edges`

* **Architecture**: 3-layer **GraphSAGE** (or R-GCN to respect edge types).
  Node features: type one-hot, degree, ASN/registrar embeddings, cert-issuer
  embedding, name char-n-gram hashing (64-d), age. Hidden 128 → 128 → 64.
  Mean-pool neighbour aggregation; ReLU; dropout 0.2.
* **Task**: link prediction. Score pair `(u,v) = σ(z_u · z_v)`.
* **Loss**: binary cross-entropy with **negative sampling** (5 neg/pos, degree-
  weighted). Observed edges = positives; random non-edges = negatives.
* **Data**: the accumulated twin corpus across all scanned targets (the
  `snapshots` table is the training set; self-supervised — no manual labels).
* **Inference**: embed nodes once per twin, score candidate non-edges, return top-k
  as `Edge(type="predicted", confidence=score)`. Same return type as today's
  Adamic–Adar baseline → zero caller change.
* **Serving**: PyTorch Geometric, exported to ONNX, batched embedding refresh on
  snapshot write.

## B.2 Temporal model → augments `evolution.forecast_subdomain_emergence`

* **Baseline shipped**: homogeneous Poisson.
* **Upgrade**: **Temporal Point Process** with a small **Temporal Transformer**
  (or LSTM) intensity head. Input: per-day event tokens (new subdomain, cert
  issuance, IP change, port change) with time2vec positional encoding. Output:
  non-stationary intensity λ(t) → horizon probabilities + expected counts, and
  next-event-type distribution (e.g. "next change is likely a new cert").
* **Loss**: negative log-likelihood of the marked TPP.
* **Data**: per-target event streams from snapshot diffs; ≥10 snapshots/target
  for signal. Cold-start falls back to the Poisson baseline automatically.

## B.3 Anomaly autoencoder → new `evolution` anomaly head

* **Architecture**: per-asset feature autoencoder (input ~32-d engineered infra
  features → 8-d bottleneck → reconstruct). Reconstruction error = anomaly score.
* **Use**: flags assets/snapshots that don't look like the org's own norm
  (sudden new ASN, off-pattern cert, atypical port set) — unsupervised, catches
  novel infra the rules miss.
* **Training**: on the org's *own* historical snapshots (one-class).

## B.4 HMM lifecycle inference → strengthens `cluster._label`

* **States**: provisioning → active → staging → decommissioning → abandoned.
* **Observations**: per-snapshot signals (resolves?, cert valid?, ports open?,
  traffic-y subdomain naming?). **Viterbi** decodes the most-likely lifecycle
  path; **forward** gives `P(abandoned | history)`.
* **Why HMM**: lifecycle is a hidden temporal state, not a static label — exactly
  the latent-sequence problem HMMs own.

## B.5 Analyst upgrade: POMDP planner

Today's greedy VoI is a 1-step lookahead. Upgrade to a **POMDP** with MCTS over
collection actions (belief = hypothesis posteriors), so the analyst can plan
multi-step collection chains ("run crt → if staging found, then rep on those
hosts only"). Same `AnalystReport` output contract.

---

## 10. Database design

### Today (shipped): SQLite — `intel/store.py`
```sql
CREATE TABLE snapshots (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    target   TEXT NOT NULL,
    ts       TEXT NOT NULL,          -- ISO-8601 UTC
    graph    TEXT NOT NULL,          -- JSON twin (document-per-snapshot)
    posture  REAL,                   -- θ mean at snapshot time
    findings INTEGER DEFAULT 0
);
CREATE INDEX idx_snap_target ON snapshots(target, ts);
```
Document-per-snapshot is correct here: we version *whole twins* for temporal
diffing, not relational graph queries. Zero-ops, ships with Python.

### At scale: Postgres + extensions
```sql
-- entities (current twin, deduped across targets)
CREATE TABLE node (
    id          TEXT PRIMARY KEY,
    type        TEXT NOT NULL,
    attrs       JSONB,
    embedding   VECTOR(64),          -- pgvector: GNN node embedding
    first_seen  TIMESTAMPTZ, last_seen TIMESTAMPTZ
);
CREATE TABLE edge (
    src TEXT, dst TEXT, type TEXT, confidence REAL, attrs JSONB,
    PRIMARY KEY (src, dst, type)
);
-- time series (TimescaleDB hypertable)
CREATE TABLE observation (
    target TEXT, ts TIMESTAMPTZ, kind TEXT, payload JSONB
);
SELECT create_hypertable('observation','ts');
```
* **pgvector** for GNN/actor-fingerprint similarity search.
* **TimescaleDB** hypertable for the event stream feeding the TPP.
* **Apache AGE** (Postgres graph) if/when ad-hoc Cypher graph queries are needed.

## 11. Backend structure

```
backend/
  modules/           # unchanged collectors (the twin's ingestion API)
  agent/             # v1 orchestrator + risk_engine (kept for /ws/recon)
  intel/             # ← v2 intelligence layer
    schemas.py       # graph + intel pydantic contracts
    graph.py         # DigitalTwin
    store.py         # SnapshotStore (temporal memory)
    bayes.py     ★   # Bayesian recon-gap (non-LLM model)
    cluster.py       # infrastructure clustering
    evolution.py     # threat-evolution forecasting
    adversary.py     # adversarial simulation
    actor_match.py   # behavioural actor matching
    relations.py     # hidden-edge prediction
    registry.py      # module capability/cost model
    agent.py         # autonomous analyst loop
  main.py            # /health, /ws/recon (v1), /ws/analyst (v2)
docs/ARCHITECTURE_V2.md
```

**API surface**: `/ws/recon` (v1 linear pipeline, untouched) and `/ws/analyst`
(v2 autonomous, streams decisions then the full intel product). v1 stays so the
redesign is additive, not a breaking rewrite.

## 12. Frontend visualization (vanilla JS, per project convention)

* **Living twin graph** — force-directed (canvas), node colour by type, edge
  style solid=observed / dashed=`predicted`, node halo = posture/anomaly.
* **Temporal scrubber** — slider over snapshots; play to watch infrastructure
  grow; new nodes pulse; migrations animate edges rerouting.
* **Attack-path overlay** — highlight internet→jewel paths, edge thickness =
  step confidence, hop labels = MITRE technique.
* **Posture radar** — controls on spokes; observed vs posterior-expected ring;
  gaps glow red proportional to confidence.
* **Hypothesis ledger** — live list with prior→posterior bars and status chips
  (confirmed/rejected/needs-evidence), plus the analyst's `request_collection`
  escalations. This is the "watch it think" panel.

## 13. Scalability

* **Collection workers**: move module runs onto an async queue (Redis/Arq);
  per-source token-bucket budgeting (HackerTarget 5/day, ip-api 45/min) shared
  across scans so the analyst's VoI planner spends a *global* budget.
* **Twin sharding**: one twin per org/target, partitioned by target hash; merges
  are local and idempotent so workers never contend.
* **Model serving**: GNN/TPP behind a batched inference service; embeddings
  refreshed on snapshot write, cached in pgvector.
* **Caching**: content-addressed by (module, target, day) so re-scans are free
  and the analyst never re-pays for fresh evidence.
* **Backpressure**: WSEvents already stream incrementally; large twins send
  deltas, not full graphs.

## 14. Competitive moat

| | SpiderFoot | Maltego | OpenCTI | **GHOSTNET v2** |
|---|---|---|---|---|
| Aggregates OSINT | ✅ | ✅ | ✅ | ✅ |
| Graph of entities | partial | ✅ (manual) | ✅ | ✅ (auto, typed) |
| **Probabilistic gap discovery** | ❌ | ❌ | ❌ | ✅ Bayesian IRT |
| **Forecasts future surface** | ❌ | ❌ | ❌ | ✅ TPP/Poisson |
| **Infers ownership w/o WHOIS** | ❌ | ❌ | ❌ | ✅ clustering |
| **Simulates attacker pivots** | ❌ | ❌ | ❌ | ✅ path search |
| **Behavioural actor match** | signatures | ❌ | signatures | ✅ behaviour |
| **Decides its own collection** | ❌ fixed | ❌ manual | ❌ | ✅ VoI analyst |

**Why an LLM wrapper can't replicate it:** every headline output is the result of
a *calibrated model over a graph* — a posterior probability, a clustering, a
shortest path, a forecast. An LLM can describe these once computed, but it cannot
*be* the Bayesian posterior, the Poisson rate, or the Dijkstra path. The moat is
the **accumulated twin corpus** (every scan trains the GNN/TPP/actor profiles)
and the **calibrated model stack** — both compound over time and neither is
promptable.

---

## Appendix: what runs today vs specified

| Capability | File | Status | Tests |
|---|---|---|---|
| Digital Twin graph | `graph.py` | **shipped** | `test_intel_graph.py` |
| Bayesian recon-gap (non-LLM) | `bayes.py` | **shipped** | `test_intel_bayes.py` |
| Infra clustering | `cluster.py` | **shipped** | `test_intel_cluster.py` |
| Threat evolution (closed-form) | `evolution.py` | **shipped** | `test_intel_evolution.py` |
| Adversarial simulation | `adversary.py` | **shipped** | `test_intel_adversary.py` |
| Actor matching | `actor_match.py` | **shipped** | (fingerprint exercised via agent) |
| Hidden-edge prediction | `relations.py` | **shipped** | (exercised via agent) |
| Temporal store | `store.py` | **shipped** | `test_intel_store.py` |
| Autonomous analyst | `agent.py` | **shipped** | `test_intel_agent.py` |
| Analyst WS endpoint | `main.py` | **shipped** | `test_intel_api.py` |
| GNN link predictor | §B.1 | specified (seam ready) | — |
| Temporal Transformer / TPP | §B.2 | specified (fallback live) | — |
| Anomaly autoencoder | §B.3 | specified | — |
| HMM lifecycle | §B.4 | specified | — |
| POMDP planner | §B.5 | specified | — |

Full suite: **128 tests passing, fully offline** (`PYTHONPATH=. pytest`).
