# GHOSTNET — Roadmap: what we're building now and next

Tiered by horizon. Each item names the **exact code seam** it touches so it can be
picked up without re-discovery. "Specified" items already have a design in
`docs/ARCHITECTURE_V2.md` §B — they are drop-in replacements for a shipped baseline.

---

## §0. Right now (active, uncommitted working tree)

**Goal: make the v2 intelligence visible.** The engines compute; this surfaces them.

- [x] Serialize the Digital Twin into the analyst output — `graph: {nodes, edges}` on
      `AnalystReport` (`backend/intel/schemas.py`, wired in `agent.py`).
- [x] **Analyst-mode frontend** — "Run Analyst" button → `/ws/analyst`, live decision
      stream, then the full intelligence product render (twin force-graph, hypothesis
      ledger, posture/recon-gap, attack paths, forecasts, clusters, actor matches,
      decision trace). `frontend/{app.js,index.html,style.css}`.
- [ ] **Close out this slice**: act on the two review passes running alongside this
      dossier (code-review + security-review), then **commit**. Likely follow-ups the
      reviews will surface:
  - Confirm `escHtml` covers *every* server-provided field in `app.js` (XSS).
  - Canvas sizing / devicePixelRatio + behaviour on large twins (force-graph perf).
  - Re-confirm the **test count** (`$env:PYTHONPATH="."; pytest -q`) and fix any drift
    from the new `graph` field / frontend wiring.
  - Note ip-api.com is **HTTP** (cleartext target) and CORS is `*` — decide if either
    needs hardening before any non-local deployment.

### Security review findings — 2026-06-26 (security-reviewer pass)

Injection-class surface is **clean**: no SQLi (`store.py` uses `?` placeholders
everywhere), `escHtml` covers every attacker-influenced free-text field in `app.js`, no
secrets in repo, no `eval`/`exec`/`pickle`/`subprocess` primitives, and internal-metadata
SSRF is not reachable (httpx fixes the URL authority). The real risk is access-control /
insecure-design. Prioritized:

- [ ] **HIGH — Unauthenticated + cross-site engine access.** `main.py` CORS `*` + both
      WebSockets `ws.accept()` with no Origin check / auth. CORS does **not** cover the WS
      handshake in Starlette, so any page the operator visits can open
      `ws://localhost:8000/ws/recon`, drive a scan from the victim machine, and read results
      (cross-site WebSocket hijack); public deploy = open relay. **Fix:** validate `Origin`
      against an allowlist at `accept`; shared-secret token for non-localhost; scope
      `allow_origins`; bind `127.0.0.1` by default.
- [ ] **HIGH — No `target` validation → active-recon relay + path injection.**
      `models/schemas.py` `target: str` is unconstrained and never checked against
      `target_type`; `rep_module` then actively port-scans the raw target via HackerTarget,
      so an unauthenticated client makes the *server* scan arbitrary hosts (attribution lands
      on the server IP). Residual SSRF is path-segment injection only (authority is fixed).
      **Fix:** validate in `TargetRequest` (domain/email regex; `ipaddress` rejecting
      private/loopback/link-local/reserved; length cap; block `/ \ ? #` + CRLF); gate the
      active `rep` module behind explicit scope consent.
- [ ] **MEDIUM — No resource bounds → DoS / third-party-API-abuse amplification.** No
      per-IP rate limit or concurrency cap; new `AsyncClient` + new `SnapshotStore` per run;
      unbounded DB growth; concurrent analyst runs → SQLite "database is locked"; `crt`
      `r.json()` uncapped. **Fix:** per-IP rate limit + concurrency semaphore; one shared
      client + store; response-size caps; prune history.
- [ ] **LOW** — ip-api over cleartext HTTP (target + verdict in plaintext, tamperable);
      raw `str(exc)` streamed to clients (leaks the absolute `reports/ghostnet.db` path);
      unpinned deps + Tabler CDN without SRI; no CSP/security headers; closed-vocab enum
      fields (`severity`, `status`, node type) interpolated raw into `innerHTML` — not
      currently exploitable (Pydantic-validated) but should still pass through `escHtml`.
- [ ] Wire `pip-audit -r backend/requirements.txt` into CI (couldn't run in review env;
      manual check of installed versions showed no known CRITICAL/HIGH CVEs).

> **Fix order:** WS Origin allowlist + auth (scope CORS) → validate `target` + gate active
> scans → rate/connection limits.

### Code review findings — 2026-06-26 (code-reviewer pass) — **REQUEST CHANGES**

Test suite **verified: 137 passed, 0 failed, fully offline** (docs say "~136" — update to
137). Math independently confirmed sound: Bayesian grid numerics, Dijkstra-over-`−log(conf)`,
and the VoI hypothesis lifecycle ("never reject an untested hypothesis" is genuinely correct
reasoning; no double-counting). XSS discipline in the new UI is solid. Merge-blockers:

- [ ] **HIGH — `graph.py:103` empty/whitespace MX crashes the whole analyst run.**
      `mx.split()[-1]` → `IndexError` on `""` / `"   "`; reachable from real partial DoH data
      (`dns_module.py:28`). `ingest_module` isn't wrapped in `agent.py:261`, so one bad MX
      aborts the entire `run_analysis` — violates the "modules never crash the pipeline"
      invariant. **Fix:** `parts = mx.split() if isinstance(mx,str) else []; if not parts:
      continue; host = parts[-1].rstrip(".")` + wrap the `ingest_module` call defensively.
- [ ] **MEDIUM — `agent.py:288-294` synthetic `internet:0.0.0.0/0` node leaks into
      `report.graph` (THIS is the in-progress `graph` work).** Kwargs eval left→right, so
      `attack_paths=simulate_attack_paths(twin)` mutates the twin (upserts INTERNET) *before*
      `graph=twin.to_dict()`. Frontend then renders a stray `internet` node, and the report
      graph is inconsistent with the persisted snapshot (`store.save` ran earlier). **Fix:**
      snapshot `graph_dict = twin.to_dict()` right after the main loop, before
      `simulate_attack_paths`; pass that. *The new test only checks keys exist, so it doesn't
      catch this.*
- [ ] **MEDIUM — `store.py:62-66` `history()` returns the OLDEST N, not newest.**
      `ORDER BY ts ASC LIMIT 50` → after 50 snapshots, forecasts diff stale/ancient history
      and miss recent arrivals. **Fix:** `ORDER BY ts DESC LIMIT ?` then reverse to ASC.
- [ ] **LOW** — LLR hypothesis evaluators treat *missing* keys as negative evidence
      (`agent.py:67-80`), unlike the unknown-vs-absent-careful IRT layer (corroborates the
      autoresearch F10/calibration note); `email` module is collected but feeds no evaluator
      (`registry.py:15` — wasted VoI budget); `traced_runner` never emits ERR on module
      failure → frontend dot stuck `running` (`main.py:73-80`); naive-tz RDAP expiry silently
      drops the forecast (`evolution.py:69`); sync SQLite on the event loop (concurrency).
- [ ] **NIT** — `detect_cert_anomaly` is implemented + tested but never wired into
      `forecast_all` (dead in prod path); stale `CONTROLS` 4-tuple comment (`bayes.py:35`,
      matches autoresearch finding); canvas not `devicePixelRatio`-scaled (blurry on HiDPI);
      add a comment by the enum `innerHTML` insertions so a future enum-widening can't open XSS.

> **Recommendation:** fix H1 + M1 + M2 before merging the analyst-UI slice. M1 in particular
> is a defect *in the change currently being made*. LOW/NIT can follow.

---

## §1. Near term — strengthen what's shipped

- [ ] **Temporal scrubber UI** — slider over `SnapshotStore` history; play to watch
      infrastructure grow, new nodes pulse, migrations animate. (Frontend; data already
      persisted in `reports/ghostnet.db`.)
- [ ] **Posture radar** — controls on spokes, observed vs posterior-expected ring, gaps
      glowing proportional to confidence. (Frontend; `PostureEstimate.controls` already
      carries `expected_presence` + `gap_confidence`.)
- [ ] **PDF / JSON export** of the `AnalystReport` (client-side; the report is already a
      single serializable object on `window.analystReport`).
- [ ] **More hypotheses** in the analyst library (`agent.py::_HYPOTHESES`) — e.g.
      certificate-mis-issuance, cloud-bucket exposure, typosquat-sibling.
- [ ] **Calibration harness** — score the Bayesian gap model against a labelled corpus
      to report reliability (are the p-values honest?). This is what turns "calibrated"
      from a claim into a measured property.

---

## §2. Mid term — the specified neural upgrades (§B drop-in seams)

Each replaces a shipped closed-form baseline; the baseline stays as automatic
cold-start fallback. **No caller changes** — same function signature, same return type.

| Upgrade | Replaces | Architecture | Data (self-supervised) |
|---|---|---|---|
| **GNN link predictor** | `relations.predict_hidden_edges` | 3-layer GraphSAGE / R-GCN, `σ(z_u·z_v)`, BCE + degree-weighted negative sampling | the accumulated twin corpus (`snapshots` table) |
| **Temporal Point Process** | `evolution.forecast_subdomain_emergence` | Temporal Transformer / LSTM intensity head, time2vec, marked-TPP NLL → non-stationary λ(t) + next-event-type | per-target event streams from snapshot diffs (≥10 snaps) |
| **Anomaly autoencoder** | new `evolution` anomaly head | ~32-d infra features → 8-d bottleneck; reconstruction error = anomaly | one-class, on the org's own history |
| **HMM lifecycle** | `cluster._label` | states provisioning→active→staging→decommissioning→abandoned; Viterbi decode + forward `P(abandoned\|history)` | per-snapshot lifecycle signals |
| **POMDP planner** | analyst's greedy 1-step VoI | MCTS over collection actions, belief = hypothesis posteriors → multi-step plans ("crt → if staging, then rep on those hosts only") | online; same `AnalystReport` contract |

**Why this ordering**: GNN + TPP compound the moat fastest — both *train on the twin
corpus that every scan grows*, so they get better with use and are not promptable.

---

## §3. Long term — scale + serving

- [ ] **Collection workers** on an async queue (Redis/Arq) with a **global** per-source
      token-bucket budget (HackerTarget 5/day, ip-api 45/min) the VoI planner spends.
- [ ] **Postgres at scale** — `node`/`edge` tables + **pgvector** (GNN + actor-fingerprint
      similarity) + **TimescaleDB** hypertable for the TPP event stream + optional Apache
      AGE for ad-hoc graph queries. (SQLite document-per-snapshot is correct for now.)
- [ ] **Model serving** — GNN/TPP behind a batched inference service; embeddings refreshed
      on snapshot write, cached in pgvector.
- [ ] **Content-addressed caching** by `(module, target, day)` so re-scans are free and
      the analyst never re-pays for fresh evidence.
- [ ] **Twin deltas over WS** for large graphs (backpressure) instead of full-graph sends.

---

## §4. Carry-over from v1 roadmap (still open)

- [ ] WAF/CDN detection module · Username enumeration (Sherlock-style) · Shodan-lite via
      HackerTarget banner grab · Diff mode (compare two scans of the same target).
- [ ] Email module: live HIBP breach lookup (currently emits a domain-search pivot note,
      since email-level HIBP needs a paid key).

---

## Definition of done for a shipped engine (the bar to clear)

1. Pure Python + stdlib/Pydantic (stays offline-testable through `MockTransport`).
2. Defensive by construction — never raises on partial/malformed module data.
3. Output is a typed Pydantic model on `AnalystReport`.
4. Covered by a `test_intel_*.py` test that exercises the *real* math, not a mock of it.
5. If it's an inference, it is labelled as such (e.g. `predicted` edges < 1.0 confidence).
