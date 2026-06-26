#  GHOSTNET

**AI-augmented OSINT intelligence platform.** Point it at a domain, IP, or email and it autonomously runs a reconnaissance pipeline against free public APIs, streams findings to your browser in real time over WebSocket, and produces a structured, risk-scored threat report.

> **No paid API keys required for core functionality.** Every data source used by the default pipeline is free and keyless.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Recon Modules](#recon-modules)
- [The Pipeline](#the-pipeline)
- [Risk Scoring](#risk-scoring)
- [WebSocket Protocol](#websocket-protocol)
- [Configuration](#configuration)
- [Testing](#testing)
- [Adding a New Module](#adding-a-new-module)
- [Known Limitations](#known-limitations)
- [Roadmap](#roadmap)
- [Legal & Ethical Use](#legal--ethical-use)

---

## Features

- **Multi-target recon** — domains, IPv4/IPv6 addresses, and email addresses.
- **Real-time streaming** — findings appear live in a terminal-style UI as each module runs, over a single WebSocket connection.
- **Seven OSINT modules** — WHOIS/RDAP, DNS, certificate transparency, geolocation, threat intelligence, port/host discovery, and email analysis.
- **Rule-based risk scoring** — every finding carries a severity; the engine aggregates them into a single `CRITICAL`/`HIGH`/`MEDIUM`/`LOW` verdict.
- **Resilient by design** — a single module failure (network error, malformed API response, rate limit) never crashes the pipeline; it degrades gracefully and the scan always completes.
- **Zero build step** — the frontend is vanilla HTML/CSS/JS served directly by FastAPI. No npm, no bundler, no framework.
- **Fully offline test suite** — 95 tests run with no network access using `httpx.MockTransport`.

---

## How It Works

```
┌──────────┐   {target, target_type}   ┌─────────────────┐
│ Browser  │ ─────────────────────────▶ │  FastAPI /ws/    │
│ (app.js) │                            │     recon        │
│          │ ◀───────────────────────── │                  │
└──────────┘   stream of WSEvents       └────────┬─────────┘
     ▲                                           │
     │  RUN / OK / WARN / ERR / DONE             ▼
     │                                  ┌──────────────────┐
     │                                  │   Orchestrator   │
     │                                  │ (pipeline runner)│
     │                                  └────────┬─────────┘
     │                                           │  one shared httpx.AsyncClient
     │              ┌────────────┬───────────────┼───────────────┬────────────┐
     │              ▼            ▼               ▼               ▼            ▼
     │          ┌───────┐   ┌───────┐       ┌───────┐       ┌───────┐    ┌───────┐
     │          │ whois │   │  dns  │  ...  │  otx  │       │  rep  │    │ email │
     │          └───┬───┘   └───┬───┘       └───┬───┘       └───┬───┘    └───┬───┘
     │              │           │               │               │            │
     │              └───────────┴───────────────┴───────────────┴────────────┘
     │                                           │  list of {module, data, findings}
     │                                           ▼
     │                                  ┌──────────────────┐
     └───────── DONE + ReconReport ──── │   Risk Engine    │
                                        │ (score + report) │
                                        └──────────────────┘
```

1. The browser opens a WebSocket to `/ws/recon` and sends a JSON target descriptor.
2. The **orchestrator** selects a module sequence based on the target type and runs each module in turn, sharing a single `httpx.AsyncClient`.
3. Each **module** queries a public API and returns raw `data` plus zero or more `findings`.
4. The orchestrator streams a `WSEvent` for every step so the UI updates live.
5. When all modules finish, the **risk engine** aggregates findings into a `ReconReport` and the server sends a final `DONE` event carrying the full report.

---

## Tech Stack

| Layer | Choice |
|---|---|
| **Backend** | Python 3.11+, FastAPI, uvicorn, httpx (async), dnspython, websockets |
| **Frontend** | Vanilla HTML / CSS / JS — no framework, no build step |
| **Styling** | Share Tech Mono (terminal) + Barlow (UI), via Google Fonts; Tabler Icons via CDN |
| **Data** | No database — session state is in-memory; reports are JSON |
| **Validation** | Pydantic v2 models for everything crossing the WebSocket boundary |
| **Testing** | pytest + pytest-asyncio, `httpx.MockTransport`, FastAPI `TestClient` |

---

## Project Structure

```
ghostnet/
├── backend/
│   ├── main.py                  # FastAPI app, /ws/recon endpoint, /health, static mount, CORS
│   ├── agent/
│   │   ├── orchestrator.py      # Async pipeline runner + module sequencing
│   │   └── risk_engine.py       # Rule-based scoring + ReconReport assembly
│   ├── modules/
│   │   ├── whois_module.py      # RDAP — registrar, expiry, status flags
│   │   ├── dns_module.py        # Google DoH — A/MX/TXT/NS/AAAA, SPF/DMARC
│   │   ├── crt_module.py        # crt.sh — subdomain enumeration + sensitive flagging
│   │   ├── geo_module.py        # ip-api.com — geolocation, proxy/hosting detection
│   │   ├── rep_module.py        # HackerTarget — nmap, hostsearch, reversedns
│   │   ├── otx_module.py        # AlienVault OTX — threat pulses, reputation
│   │   └── email_module.py      # Email validation, MX check, username permutations
│   ├── models/
│   │   └── schemas.py           # Pydantic: TargetRequest, WSEvent, Finding, ReconReport
│   ├── tests/                   # Offline pytest suite (95 tests)
│   │   ├── conftest.py          # make_client fixture (MockTransport AsyncClient)
│   │   ├── test_schemas.py
│   │   ├── test_risk_engine.py
│   │   ├── test_orchestrator.py
│   │   ├── test_modules.py
│   │   └── test_api.py
│   ├── requirements.txt         # Runtime dependencies
│   └── requirements-dev.txt     # Runtime + test dependencies
├── frontend/
│   ├── index.html               # Single-page app
│   ├── style.css                # Dark terminal theme (CSS variables)
│   └── app.js                   # WebSocket client, terminal renderer, report builder
├── reports/                     # Exported JSON reports (gitignored)
├── pytest.ini                   # Test configuration
├── .env.example                 # Optional API-key template
├── .gitignore
├── CLAUDE.md                    # Architecture & conventions (source of truth for contributors)
└── README.md                    # This file
```

---

## Quick Start

### Prerequisites

- **Python 3.11+** (the codebase uses 3.10+ union syntax and modern typing)
- A modern browser

### 1. Clone & enter the project

```bash
git clone <your-repo-url> ghostnet
cd ghostnet
```

### 2. Create a virtual environment

**Linux / macOS**
```bash
python -m venv venv
source venv/bin/activate
```

**Windows (PowerShell)**
```powershell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Run the server

The app is a package (`backend.main:app`), so it must be launched from the **project root** with the root on `PYTHONPATH`.

**Linux / macOS**
```bash
PYTHONPATH=. uvicorn backend.main:app --reload --port 8000
```

**Windows (PowerShell)**
```powershell
$env:PYTHONPATH = "."
uvicorn backend.main:app --reload --port 8000
```

### 5. Open the app

Navigate to **http://localhost:8000** — FastAPI serves the frontend from the same origin, so the WebSocket connects automatically.

---

## Usage

1. Enter a **target** in the sidebar (e.g. `example.com`, `1.1.1.1`, or `admin@example.com`).
2. Pick the matching **type** (Domain / IP / Email).
3. Click **Run Scan**.
4. Watch the terminal stream findings live; module dots turn from idle → running → done/error.
5. When the scan finishes, the **report panel** renders the aggregated risk verdict and a severity-sorted findings table.

All raw module data is also stashed on `window.reconSession` in the browser for inspection via DevTools.

### Safe test targets

| Target | Type | Why it's safe |
|---|---|---|
| `example.com` | domain | IANA reference domain |
| `github.com` | domain | Large attack surface, rich CT data |
| `1.1.1.1` | ip | Cloudflare DNS — known clean |
| `8.8.8.8` | ip | Google DNS — known clean |
| `scanme.nmap.org` | domain | Nmap's official scan-me host |

---

## Recon Modules

Every module implements the **same contract**:

```python
async def run(target: str, client: httpx.AsyncClient) -> dict:
    return {
        "module": "name",
        "data": { ... },        # raw API response data
        "findings": [           # zero or more findings
            {"severity": "HIGH", "title": "...", "detail": "..."}
        ],
    }
```

| Module | Source API | Keyless? | What it finds |
|---|---|---|---|
| **whois** | RDAP (`rdap.org`) | ✅ | Registrar, expiry (HIGH if < 30 days), missing `clientDeleteProhibited` lock |
| **dns** | Google DoH (`dns.google`) | ✅ | A/MX/TXT/NS/AAAA records; flags missing MX, SPF, DMARC |
| **crt** | crt.sh | ✅ | Subdomain enumeration from CT logs; flags sensitive names (`admin`, `vpn`, `dev`…) and large footprints |
| **geo** | ip-api.com | ✅ | Geolocation, ASN/org; flags proxy/VPN (HIGH) and hosting/datacenter IPs (MEDIUM) |
| **otx** | AlienVault OTX | ✅ | Threat-intel pulses (CRITICAL), malware tags (HIGH), negative reputation score (HIGH); auto-detects IPv4/IPv6/domain |
| **rep** | HackerTarget | ✅ | Port scan (nmap), host search, reverse DNS; flags dangerous open ports (21/22/23/25/445/3389/5900/6379/27017) |
| **email** | Google DoH | ✅ | Email validation, domain extraction, MX deliverability check (HIGH if no MX), username permutation generator, HIBP pivot note |

> **Severity scale:** `CRITICAL` · `HIGH` · `MEDIUM` · `LOW` · `INFO`

---

## The Pipeline

The orchestrator chooses which modules run based on the target type:

```python
PIPELINE = {
    "domain": ["whois", "dns", "crt", "geo", "otx", "rep"],
    "ip":     ["geo", "otx", "rep"],
    "email":  ["email", "whois", "dns"],
}
```

For **email** targets, the `whois` and `dns` modules automatically operate on the **domain part** of the address (`admin@example.com` → `example.com`), so they return meaningful results instead of failing on the raw email string.

All modules in a pipeline share **one** `httpx.AsyncClient` (created by the orchestrator) — modules never create their own client. This is both a performance choice and the seam that makes the test suite fully offline (see [Testing](#testing)).

---

## Risk Scoring

The risk engine aggregates **all** findings from **all** modules and reduces them to a single verdict:

| Verdict | Condition |
|---|---|
| **CRITICAL** | Any `CRITICAL` finding is present |
| **HIGH** | Any `HIGH` finding is present |
| **MEDIUM** | Any `MEDIUM` finding is present |
| **LOW** | No significant findings |

`INFO` findings are informational and never escalate the overall risk level. The engine is also defensive: any malformed finding returned by a module is silently skipped during report assembly rather than crashing the scan.

---

## WebSocket Protocol

**Endpoint:** `ws://<host>/ws/recon`

### Client → Server (one message)

```json
{ "target": "example.com", "target_type": "domain" }
```

`target_type` must be one of `"domain"`, `"ip"`, `"email"`.

### Server → Client (stream of `WSEvent`)

```jsonc
{ "tag": "RUN",  "module": "dns",    "message": "Starting dns...",      "data": null }
{ "tag": "OK",   "module": "dns",    "message": "dns complete",          "data": { /* raw */ } }
{ "tag": "WARN", "module": "dns",    "message": "Missing SPF record",    "data": { /* finding */ } }
{ "tag": "ERR",  "module": "rep",    "message": "<error text>",          "data": null }
{ "tag": "DONE", "module": "engine", "message": "",                      "data": { /* ReconReport */ } }
```

| Tag | Meaning |
|---|---|
| `RUN` | A module has started |
| `OK` | A module completed, or a low/info finding |
| `WARN` | A `MEDIUM`/`HIGH`/`CRITICAL` finding |
| `ERR` | A module (or the server) errored — the pipeline continues |
| `DONE` | Terminal event; `data` is the full `ReconReport` |

A `DONE` event is **always** sent — even if the request is invalid or every module fails — so clients can reliably detect completion.

### `ReconReport` shape

```jsonc
{
  "target": "example.com",
  "target_type": "domain",
  "risk_level": "CRITICAL",
  "findings": [ { "severity": "HIGH", "title": "...", "detail": "..." } ],
  "modules": { "dns": { "data": {...}, "findings": [...] }, "...": {} },
  "timestamp": "2026-06-06T12:33:29.685513Z"
}
```

### Other HTTP endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness probe → `{"status": "ok"}` |
| `GET` | `/` | Serves the frontend SPA (static mount) |

CORS is open (`allow_origins=["*"]`) to ease local development and external clients.

---

## Configuration

All environment variables are **optional** and only enhance specific modules. Copy the template:

```bash
cp .env.example .env
```

```bash
# .env
ABUSEIPDB_KEY=          # (future) IP abuse score — 1000 checks/day free
VIRUSTOTAL_KEY=         # (future) domain/hash reputation
SHODAN_KEY=             # (future) banner/port intel
```

The default pipeline runs entirely without any of these.

---

## Testing

The suite is **fully offline and deterministic** — no network calls, no API keys. This works because modules receive their HTTP client by injection, so tests hand them a client backed by `httpx.MockTransport`, which intercepts every request in-process and returns canned responses. The real module parsing/scoring logic still runs; only the bytes "from the wire" are faked.

```bash
# Install runtime + test dependencies
pip install -r backend/requirements-dev.txt

# Run the suite (PYTHONPATH must include the repo root)
PYTHONPATH=. pytest            # Linux/macOS
$env:PYTHONPATH="."; pytest    # Windows PowerShell
```

### What's covered (95 tests)

| File | Focus |
|---|---|
| `test_schemas.py` | Pydantic model validation — valid/invalid enums, defaults |
| `test_risk_engine.py` | Scoring ladder + report aggregation, invalid-finding skipping |
| `test_orchestrator.py` | Pipeline routing, event streaming, severity→tag mapping, failure isolation, "DONE always fires" |
| `test_modules.py` | Each module's parsing/findings, the interface contract, and failure modes — via `MockTransport` |
| `test_api.py` | `/health` and the `/ws/recon` WebSocket framing — via FastAPI `TestClient` |

> **Note:** the `dns` and `email` modules isolate failures at the per-query level, treating an unreachable resolver as "record absent." A network outage during a DNS scan can therefore surface as MEDIUM findings (e.g. "Missing SPF record"). This is intentional graceful degradation.

---

## Adding a New Module

1. Create `backend/modules/<name>_module.py` with `async def run(target, client) -> dict` following the [module contract](#recon-modules).
2. Wrap all HTTP calls in `try/except` — return empty `findings` on failure, **never raise**.
3. Register the module name in the `PIPELINE` and `_MODULE_MAP` in `backend/agent/orchestrator.py`.
4. Add a sidebar entry in `frontend/index.html` with `id="mod-<name>"` and add `<name>` to `MODULE_NAMES` in `frontend/app.js`.
5. Add tests in `backend/tests/test_modules.py` using the `make_client` fixture.

See `CLAUDE.md` for the full contributor contract and coding conventions.

---

## Known Limitations

- **HackerTarget free tier:** ~5 API calls/day per source IP — the `rep` module may hit this limit (it surfaces an `INFO` finding when it does).
- **crt.sh:** occasionally returns 503 / non-JSON under load — handled gracefully (module returns no findings).
- **ip-api.com:** free tier is rate-limited (~45 req/min) and **HTTP-only** (the target is sent in cleartext).
- **OTX:** anonymous access works but is rate-limited (~100 req/min); some data may require an API key.
- **Email module:** HIBP **email-level** breach lookup requires a paid key, so the module emits a domain-search pivot note rather than performing a live breach check.

---

## Roadmap

- [ ] **Entity graph** — D3.js force layout linking discovered subdomains/IPs
- [ ] **PDF export** — client-side jsPDF report generation
- [ ] **Session history** — SQLite persistence for past scans
- [ ] **WAF/CDN detection** module
- [ ] **Username enumeration** module (Sherlock-style, async)
- [ ] **Diff mode** — compare two scans of the same target over time
- [ ] **Shodan-lite** via HackerTarget banner grab

---

## Legal & Ethical Use

> ⚠️ **Only scan targets you own or have explicit written permission to test.**

GHOSTNET queries third-party public APIs and performs reconnaissance that may be logged by those services and by the target. Unauthorized scanning may violate computer-misuse laws, terms of service, and acceptable-use policies in your jurisdiction. This tool is provided for **authorized security testing, education, and defensive research** only. You are solely responsible for how you use it.

---

<p align="center"><em>Built for recon. Use responsibly.</em> 👻</p>
