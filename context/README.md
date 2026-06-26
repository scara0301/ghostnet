# GHOSTNET — Context Dossier

This folder is the **single-source briefing pack** for GHOSTNET. It exists so any
human or AI agent can pick up the project cold and understand *what it is, where it
stands, where it's going, and why it wins* — without reverse-engineering the code.

> Naming note: this folder is called `context/` (not `module/`) to avoid collision
> with `backend/modules/`, which is a real code package. Same intent — a portable
> bundle of project context.

## 60-second orientation

GHOSTNET is an **AI-augmented OSINT intelligence platform**. v1 was a recon pipeline
that streamed API results to a browser. **v2 (the current focus)** is the part that
matters: an *autonomous intelligence analyst* that builds a continuously-updated
**Digital Twin** of a target's infrastructure and runs a stack of **calibrated,
non-LLM statistical models** over it to **produce intelligence that existed in none
of its inputs** — posterior probabilities, forecasts, clusterings, attack paths.

The thesis in one line: **an LLM wrapper paraphrases OSINT; GHOSTNET computes new
inferences over a graph.** That distinction is the entire moat.

## The four documents

| File | What it answers |
|---|---|
| [`PROJECT_CONTEXT.md`](./PROJECT_CONTEXT.md) | What GHOSTNET is, the architecture, and exactly what is **shipped vs in-progress** right now. |
| [`ROADMAP.md`](./ROADMAP.md) | What we are **implementing now** and what is **planned next** (near / mid / long term). |
| [`COMPETITIVE_MOAT.md`](./COMPETITIVE_MOAT.md) | **How it beats** SpiderFoot / Maltego / OpenCTI / generic "ChatGPT-over-OSINT" tools. |

## Authoritative sources (don't let this folder drift from them)

- **`docs/ARCHITECTURE_V2.md`** — implementation-grade design spec (the v2 brief). The
  most detailed document in the repo; this dossier summarizes and operationalizes it.
- **`CLAUDE.md`** — coding conventions + module contract (source of truth for contributors).
- **`README.md`** — v1 user-facing docs (pipeline, modules, WS protocol, testing).
- **The test suite** — `backend/tests/test_intel_*.py`. Every "shipped" claim here is
  backed by an offline test. If a claim isn't tested, it's in ROADMAP, not CONTEXT.

## Status at a glance (as of this dossier)

- **Backend intelligence layer (`backend/intel/`)**: shipped + tested, fully offline.
- **In-progress (uncommitted)**: Digital Twin graph serialized into `AnalystReport`
  (`graph` field) and a full **analyst-mode frontend** (force-directed twin canvas +
  hypothesis ledger + posture/recon-gap + attack paths + forecasts + clusters + actor
  matches + decision trace), reached via a new **"Run Analyst"** button (`/ws/analyst`).
- **Specified, not built** (§B of the architecture doc): the neural upgrades — GNN link
  predictor, Temporal Point Process, anomaly autoencoder, HMM lifecycle, POMDP planner.
  Each has a defined drop-in seam so it replaces a shipped baseline without caller changes.
