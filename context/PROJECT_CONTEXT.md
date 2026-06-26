# GHOSTNET — Project Context

## 1. What it is

GHOSTNET takes a **target** (domain, IPv4/IPv6, or email) and autonomously runs
reconnaissance against **free, keyless public APIs**, then reasons over the results
to emit a structured, risk-scored intelligence product. No paid keys are required for
core functionality; the whole system runs offline-testable.

There are two operating modes, exposed as two WebSocket endpoints:

| Mode | Endpoint | Behaviour |
|---|---|---|
| **Recon** (v1) | `/ws/recon` | Fixed linear pipeline. Runs every module for the target type, streams `RUN/OK/WARN/ERR` events, ends with a rule-scored `ReconReport`. Simple, fast, deterministic. |
| **Analyst** (v2) | `/ws/analyst` | **Autonomous.** Forms hypotheses, decides *what to collect next by value of information*, updates beliefs with Bayesian odds, stops early or escalates, and emits a full `AnalystReport` (posture, clusters, forecasts, attack paths, actor matches, predicted edges, hypothesis ledger, Digital Twin graph). |

v1 is intentionally **kept**, so v2 is additive — not a breaking rewrite.

## 2. The thesis (why this is not an "AI wrapper")

A ChatGPT-over-OSINT product takes API output and rephrases it: the *intelligence
content is unchanged, only the prose is new.* GHOSTNET inverts that — every headline
output is the result of a **calibrated model over a graph**, not a paraphrase:

| Input (observed) | Output (newly created intelligence) |
|---|---|
| "SPF record absent" | "Given posture θ=0.81, SPF *should* exist with p=0.97 → its absence is a HIGH-confidence anomaly" — a probability nowhere in the input. |
| A list of subdomains | "These 6 assets are one org, these 2 are staging, this cluster is abandoned" — ownership + lifecycle no API returned. |
| Two scans a week apart | "λ=0.2 new subdomains/day → 99.7% chance of new attack surface in 30d" — a forecast. |
| Ports + subdomains | A confidence-scored attack graph from internet → crown jewel — a pivot plan. |

An LLM can *describe* a posterior once computed, but it cannot **be** the Bayesian
posterior, the Poisson rate, or the Dijkstra path. See `COMPETITIVE_MOAT.md`.

## 3. Architecture (layers, bottom → top)

```
COLLECTION   backend/modules/   whois·dns·crt·geo·otx·rep·email
             (unchanged v1 contract: async run(target, client) -> {module,data,findings})
                       │ ingest_module()
DIGITAL TWIN backend/intel/graph.py + store.py
             typed property graph (idempotent, confidence-aware merge) + SQLite snapshots
                       │
INFERENCE    backend/intel/  bayes·cluster·evolution·adversary·actor_match·relations
             calibrated non-LLM models that emit NEW intelligence over the twin
                       │
AUTONOMY     backend/intel/agent.py
             hypothesis ledger · value-of-information planner · Bayesian belief update · escalation
                       │ WSEvent stream (/ws/analyst)
PRESENTATION frontend/  twin graph · hypothesis ledger · posture radar · attack overlay · decision trace
```

The collection layer is the **ingestion API for the twin** — its v1 `{module, data,
findings}` contract is untouched, which is also what keeps everything offline-testable.

## 4. The intelligence engines (all SHIPPED + tested)

| Engine | File | What it computes | Method |
|---|---|---|---|
| **Digital Twin** | `graph.py` | Single source of truth: typed nodes (domain, ip, asn, cert, …) + edges (resolves_to, shares_cert, `predicted`, …). | Idempotent merge: re-ingest refreshes `last_seen`, takes `max(confidence)` — a *living* model, enables temporal diffing. |
| **Bayesian Recon-Gap** ★ | `bayes.py` | "What control *should* exist but is absent?" with a calibrated probability. | **Item Response Theory (2PL)**: latent maturity θ on a 101-pt grid, exact Bayesian update, Beta(1.6,1.6) prior. Same missing SPF is HIGH for θ=0.81, INFO for θ=0.18. |
| **Infra Clustering** | `cluster.py` | "These assets are one org" + active/staging/abandoned labels. | Single-linkage union-find over shared cert SANs, /24, ASN, name-token overlap; lifecycle features label clusters. |
| **Threat Evolution** | `evolution.py` | Forecasts: new subdomains, expiry lapse, cert anomaly, infra migration. | Closed-form: homogeneous Poisson, logistic hazard, robust median/MAD z-score, snapshot set-diff. |
| **Adversarial Sim** | `adversary.py` | Confidence-scored attack paths internet → crown jewel, MITRE-tagged. | Dijkstra over `−log(confidence)` (max-product → min-sum). **Simulation only, never live exploitation.** |
| **Actor Matching** | `actor_match.py` | "This infra is built like actor X" — matches even on brand-new IPs. | Behavioural fingerprint (DGA-ish naming, fresh domains, bulletproof ASN, fast-flux, punycode) → weighted-cosine vs profiles. |
| **Hidden-Edge Prediction** | `relations.py` | Inferred relationships not directly observed. | Adamic–Adar link prediction; output typed `predicted` with sub-1.0 confidence (inferred ≠ observed). |
| **Temporal Store** | `store.py` | Versioned twin snapshots for temporal intelligence. | SQLite document-per-snapshot; indexed by `(target, ts)`. |

★ = the flagship non-LLM model.

## 5. The autonomous analyst (`agent.py`) — the behaviour that makes it an *analyst*

- **Belief state**: twin + module results + hypothesis ledger + budget.
- **Hypothesis library** (H1 weak-email, H2 staging-exposed, H3 shared-infra,
  H4 malicious-like, H5 exploitable, H6 expiry/takeover). Each declares a prior, the
  modules whose evidence bears on it, and an evaluator returning a **log-likelihood-ratio**.
- **Bayesian update**: `logit(posterior) = logit(prior) + Σ LLR(evidence)`.
- **Planning = value of information**: run the module that touches the most *live*
  hypothesis uncertainty per unit cost,
  `VoI(m) = Σ_h (1−|2p_h−1|)·[m relevant] / cost(m)`. It runs cheap/high-signal modules
  first and **skips zero-VoI modules entirely** (e.g. whois when nothing depends on it).
- **Lifecycle**: confirmed (p≥.75) / rejected (p≤.20) / needs_evidence / open. A
  hypothesis is **never rejected while it still has untested collection** — you cannot
  reject what you never checked.
- **Early stop** when marginal VoI < ε ("enough evidence"); **escalates**
  `request_collection` for unresolved-but-promising hypotheses (0.35 ≤ p ≤ 0.65) with
  nothing left to run.
- **Failure isolation**: a collection error is captured into the result, never crashes the loop.

Output is an `AnalystReport` (`backend/intel/schemas.py`) streamed live over `/ws/analyst`.

## 6. What is SHIPPED vs IN-PROGRESS vs SPECIFIED

### ✅ Shipped (real, tested, fully offline)
All eight engines above + the analyst loop + the `/ws/analyst` endpoint
(`backend/main.py`). Test suite **verified at 137 passing, 0 failed, fully offline**
(the architecture doc's "~136" is slightly stale) — confirmed by the code-review pass,
see `ROADMAP.md` §0.

### 🚧 In-progress (current uncommitted working tree)
The **presentation layer** for analyst mode — i.e. making the intelligence *visible*:
- **Backend**: `AnalystReport` now carries the Digital Twin (`graph: {nodes, edges}`),
  serialized in `agent.py`; covered by a new test (`test_agent_report_carries_twin_graph`).
- **Frontend** (`frontend/app.js` +377, `index.html` +48, `style.css` +158):
  - New **"Run Analyst"** button + mode hint next to "Run Scan".
  - `connectAnalyst()` drives `/ws/analyst`, rendering planning decisions live, then a
    full intelligence product: **force-directed Digital Twin canvas** (node colour by
    type, dashed edges = `predicted`), **hypothesis ledger** with prior→posterior bars
    and status chips, **posture + Bayesian recon-gap** view, **attack paths**,
    **forecasts**, **infrastructure clusters**, **threat-actor matches**, and the
    **analyst decision trace**.
  - All server-provided strings rendered via an `escHtml` helper (XSS surface — being
    verified by the security-review pass).

### 📐 Specified, not built (§B of `docs/ARCHITECTURE_V2.md`)
Neural upgrades, each with a **drop-in seam** that replaces a shipped baseline with no
caller change: GNN link predictor (→ `relations.predict_hidden_edges`), Temporal Point
Process / Temporal Transformer (→ `evolution.forecast_*`), anomaly autoencoder, HMM
lifecycle inference (→ `cluster._label`), POMDP multi-step planner (→ the analyst's
greedy VoI). See `ROADMAP.md`.

## 7. Where everything lives (file map)

```
backend/
  main.py              /health · /ws/recon (v1) · /ws/analyst (v2) · static mount · CORS
  agent/               v1 orchestrator + risk_engine (kept for /ws/recon)
  modules/             collectors — whois/dns/crt/geo/otx/rep/email (the twin's ingestion API)
  models/schemas.py    v1 WS-boundary contracts (TargetRequest, WSEvent, Finding, ReconReport)
  intel/               ← v2 intelligence layer
    schemas.py         graph + intel Pydantic contracts (Node, Edge, PostureEstimate, AnalystReport…)
    graph.py           DigitalTwin (typed property graph)
    store.py           SnapshotStore (temporal memory, SQLite → reports/ghostnet.db)
    bayes.py       ★   Bayesian recon-gap (IRT)
    cluster.py         infrastructure clustering
    evolution.py       threat-evolution forecasting
    adversary.py       adversarial attack-path simulation
    actor_match.py     behavioural actor matching
    relations.py       hidden-edge link prediction
    registry.py        module capability/cost model (MODULE_COST, default_runner)
    agent.py           autonomous analyst loop (VoI planner + Bayesian beliefs)
  tests/               offline pytest suite (test_intel_*.py + v1 tests)
frontend/              vanilla HTML/CSS/JS — recon UI + analyst intelligence UI
docs/ARCHITECTURE_V2.md   the implementation-grade design spec
context/               ← this dossier
```

## 8. How to run / test

```powershell
# Run the server (Windows PowerShell) from repo root
$env:PYTHONPATH = "."
uvicorn backend.main:app --reload --port 8000     # open http://localhost:8000

# Offline test suite
pip install -r backend/requirements-dev.txt
$env:PYTHONPATH = "."; pytest -q
```

The suite is fully offline: modules receive their `httpx.AsyncClient` by injection, so
tests hand them a `MockTransport`-backed client. Real parsing/scoring logic runs; only
the bytes "from the wire" are faked. No network, no keys.
