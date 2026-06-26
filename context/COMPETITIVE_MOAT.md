# GHOSTNET — Competitive Moat: how it beats the alternatives

The question this answers: *"There are a hundred OSINT tools and a thousand
ChatGPT-wrappers. Why is this one different?"* Short answer: **everyone else
aggregates or paraphrases; GHOSTNET infers.** Every headline output is a calibrated
model's verdict over a graph — a thing a competitor's pipeline doesn't compute and a
language model fundamentally cannot be.

---

## 1. Versus the OSINT incumbents

| Capability | SpiderFoot | Maltego | OpenCTI | **GHOSTNET v2** |
|---|---|---|---|---|
| Aggregates OSINT | ✅ | ✅ | ✅ | ✅ |
| Graph of entities | partial | ✅ (manual) | ✅ | ✅ (auto, typed) |
| **Probabilistic gap discovery** | ❌ | ❌ | ❌ | ✅ Bayesian IRT |
| **Forecasts future attack surface** | ❌ | ❌ | ❌ | ✅ TPP / Poisson |
| **Infers ownership without WHOIS** | ❌ | ❌ | ❌ | ✅ clustering |
| **Simulates attacker pivots** | ❌ | ❌ | ❌ | ✅ path search |
| **Behavioural actor match** | signatures | ❌ | signatures | ✅ behaviour (survives IP rotation) |
| **Decides its own collection** | ❌ fixed | ❌ manual | ❌ | ✅ VoI analyst |

**The pattern**: incumbents stop at *collection + display*. They show you what exists.
GHOSTNET's whole stack starts where they stop — it computes what the observations
*imply*: a probability, a cluster, a forecast, a path.

### Point-by-point

- **vs SpiderFoot** (automated aggregator): SpiderFoot fans out collectors and lists
  results. It has no posterior, no forecast, no attack-path search, and a *fixed* module
  graph. GHOSTNET's analyst **chooses** collection by value-of-information and **scores**
  the results with calibrated models.
- **vs Maltego** (manual link-analysis): Maltego is a brilliant canvas, but the *analyst
  is the intelligence* — a human drags transforms and draws conclusions. GHOSTNET
  **automates the analyst**: hypothesis ledger, belief updates, escalation.
- **vs OpenCTI** (threat-intel platform / STIX store): OpenCTI is a system of record for
  intel *humans already produced*. GHOSTNET is a system that *produces* intel — the
  upstream step OpenCTI assumes already happened.

---

## 2. Versus "ChatGPT-over-OSINT" wrappers (the real competition in 2026)

This is the category GHOSTNET is explicitly designed to beat, because it's the easy
thing everyone builds. A wrapper pipes API output into a prompt and returns prose. The
**intelligence content is unchanged; only the wording is new.**

GHOSTNET inverts it — the output is a *number a model computed*, not a sentence:

| A wrapper says | GHOSTNET computes |
|---|---|
| "The domain is missing an SPF record, which could allow spoofing." | "P(SPF present \| θ=0.81)=0.97 → absence is a HIGH-confidence **anomaly**; for θ=0.18 the same absence is INFO." A **calibrated posterior**, target-specific. |
| "I found several subdomains including dev.x and staging.y." | "Assets {a,b,c,d,e,f} are **one org** (shared cert SANs + /24); {dev.x, staging.y} are a **staging** cluster; cluster Z is **abandoned**." Ownership + lifecycle. |
| "You should monitor for new infrastructure." | "λ=0.2/day → **99.7%** chance of new attack surface in 30d; cert cadence **z=4.1** anomaly." A forecast with a probability. |
| "An attacker might pivot through open ports." | A **Dijkstra-optimal**, confidence-scored path internet→crown-jewel with MITRE technique labels and a path confidence = ∏ step confidences. |

### Why an LLM wrapper *cannot* replicate this (not "hasn't yet" — *cannot*)

1. **The answer is the output of a calibrated model, not a paraphrase.** An LLM can
   *describe* a Bayesian posterior, a Poisson rate, or a shortest path once you've
   computed it — but it cannot **be** the posterior, the rate, or the path. Ask it for a
   number and you get a plausible-sounding hallucination, not a calibrated probability.
2. **The moat compounds and isn't promptable.** Two assets that compound with every scan:
   - **The accumulated twin corpus** — every scan grows the `snapshots` training set that
     feeds the GNN link predictor and the Temporal Point Process. More usage → better
     models. A prompt has no such memory.
   - **The calibrated model stack** — IRT difficulties/discriminations fittable by EM,
     actor profiles minable by DBSCAN over historical campaigns. These are *learned
     parameters*, not instructions you can copy into a system prompt.
3. **Determinism + auditability.** Every verdict traces to an exact computation
   (log-odds accumulation, a grid posterior, a min-sum path). Reproducible, explainable,
   and defensible in a report — properties a stochastic generator cannot guarantee.

---

## 3. The one-sentence moat

> **An LLM wrapper rephrases the intelligence in its input; GHOSTNET produces
> intelligence that was in none of its inputs — a posterior, a clustering, a forecast,
> a shortest path — and gets sharper every scan because each scan trains the models.**

---

## 4. Honest risks to the moat (so we defend it deliberately)

- **The neural upgrades are specified, not built** (§B). The *baselines* are real and
  tested, but the headline "compounds with use" story is strongest once the GNN/TPP are
  training on the corpus. Priority: ship GNN + TPP (see `ROADMAP.md` §2).
- **Calibration is currently asserted by construction, not measured.** The IRT model is
  principled, but "calibrated" should be *demonstrated* on a labelled corpus
  (`ROADMAP.md` §1, calibration harness). That measurement is itself a differentiator.
- **Seed parameters are illustrative** (actor profiles, IRT difficulties). They're
  defensible as priors, but the production story (EM-fit / DBSCAN-mined) needs the corpus
  to exist. The architecture is built for it; the data has to accumulate.
- **A well-funded incumbent could bolt a model layer on.** True — but they'd be starting
  the corpus from zero, and their products are architected around *display*, not a
  continuously-updated twin. The twin + the offline-testable model discipline is the head start.
