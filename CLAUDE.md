# GHOSTNET — Claude Code Instructions

## Project Overview
GHOSTNET is an AI-augmented OSINT intelligence platform. It takes a target (domain, IP, or email) and autonomously runs a recon pipeline using free public APIs, streams findings in real-time over WebSocket, and generates a structured threat report with rule-based risk scoring.

**No paid API keys required for core functionality.**

---

## Tech Stack
- **Backend**: Python 3.11+, FastAPI, uvicorn, httpx (async), dnspython, websockets
- **Frontend**: Vanilla HTML/CSS/JS — no framework, no build step
- **Styling**: Share Tech Mono (terminal), Barlow (UI) — loaded from Google Fonts
- **Data**: No database — session state in memory, reports exported as JSON
- **Icons**: Tabler Icons (CDN)

---

## Project Structure
```
ghostnet/
├── backend/
│   ├── main.py                  # FastAPI app, WebSocket endpoint, static file mount
│   ├── agent/
│   │   ├── orchestrator.py      # Async pipeline runner, module sequencing
│   │   └── risk_engine.py       # Rule-based risk scoring, report generation
│   ├── modules/
│   │   ├── whois_module.py      # RDAP — registrar, expiry, status flags
│   │   ├── dns_module.py        # Google DoH — A/MX/TXT/NS/AAAA, SPF/DMARC
│   │   ├── crt_module.py        # crt.sh — subdomain enumeration, sensitive flagging
│   │   ├── geo_module.py        # ip-api.com — geolocation, proxy/hosting detection
│   │   ├── rep_module.py        # HackerTarget — nmap, hostsearch, reversedns
│   │   └── otx_module.py        # AlienVault OTX — threat pulses, malware families
│   ├── models/
│   │   └── schemas.py           # Pydantic models: TargetRequest, WSEvent, Finding, ReconReport
│   └── requirements.txt
├── frontend/
│   ├── index.html               # Single page app
│   ├── style.css                # Dark terminal theme
│   └── app.js                   # WebSocket client, terminal renderer, report builder
├── reports/                     # Exported JSON reports (gitignored)
├── .env.example
├── .gitignore
└── CLAUDE.md                    # This file
```

---

## Architecture

### WebSocket Event Flow
```
Client sends → { target: "example.com", target_type: "domain" }

Server streams → WSEvent per module:
  { tag: "RUN",  module: "dns",   message: "Starting DNS enumeration..." }
  { tag: "OK",   module: "dns",   message: "A: 93.184.216.34", data: {...} }
  { tag: "WARN", module: "dns",   message: "Missing SPF record", data: {...} }
  { tag: "DONE", module: "engine", data: ReconReport }
```

### Pipeline Per Target Type
```python
PIPELINE = {
    "domain": ["whois", "dns", "crt", "geo", "otx", "rep"],
    "ip":     ["geo", "otx", "rep"],
    "email":  ["whois", "dns"]
}
```

### Module Interface (every module must follow this)
```python
async def run(target: str, client: httpx.AsyncClient) -> dict:
    return {
        "module": "module_name",
        "data": { ... },          # raw API response data
        "findings": [             # zero or more findings
            {
                "severity": "HIGH",   # CRITICAL | HIGH | MEDIUM | LOW | INFO
                "title": "...",
                "detail": "..."
            }
        ]
    }
```

### Risk Scoring Logic
```
CRITICAL  → any CRITICAL finding present
HIGH      → 2 or more HIGH findings
MEDIUM    → any MEDIUM finding present
LOW       → no significant findings
```

---

## Free APIs Used (No Keys Required)

| Module | API | Endpoint |
|---|---|---|
| WHOIS | RDAP | `https://rdap.org/domain/{target}` |
| DNS | Google DoH | `https://dns.google/resolve?name={}&type={}` |
| Subdomains | crt.sh | `https://crt.sh/?q=%.{domain}&output=json` |
| Geolocation | ip-api.com | `http://ip-api.com/json/{ip}?fields=...` |
| Threat Intel | AlienVault OTX | `https://otx.alienvault.com/api/v1/indicators/` |
| Port Scan | HackerTarget | `https://api.hackertarget.com/nmap/?q={}` |
| Host Search | HackerTarget | `https://api.hackertarget.com/hostsearch/?q={}` |
| Reverse DNS | HackerTarget | `https://api.hackertarget.com/reversedns/?q={}` |

---

## Coding Conventions

### Python
- All module functions are `async def run(target, client)` — no exceptions
- Use `httpx.AsyncClient` passed from orchestrator — never create new clients inside modules
- All HTTP calls wrapped in `try/except httpx.HTTPError` — modules never crash the pipeline
- Return empty findings list `[]` on failure, never raise
- Type hints on all function signatures
- Pydantic models for all data crossing the WebSocket boundary
- No `print()` — use the WSEvent stream for all output

### JavaScript
- Vanilla JS only — no React, no Vue, no jQuery
- WebSocket connection managed in `app.js` — single instance, reconnect on drop
- Terminal log lines created via `createLogLine(tag, message)` DOM factory
- Module dot states: `idle` | `running` | `done` | `error` — set via `setModuleState(name, state)`
- All API response data stored in `window.reconSession` object
- Report rendered from `DONE` WSEvent data only — never construct it incrementally

### CSS
- CSS variables for all colors — defined in `:root` in `style.css`
- Dark theme only: `--c-bg: #0a0c0f`
- Terminal font: `Share Tech Mono`, UI font: `Barlow`
- No frameworks, no Tailwind — raw CSS only

---

## Running Locally

```bash
# Backend
cd ghostnet/backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Frontend is served by FastAPI at http://localhost:8000
# Open browser → http://localhost:8000
```

---

## Running Tests

The suite is fully offline — modules are exercised through `httpx.MockTransport`,
the orchestrator via stubbed modules, and the WebSocket endpoint via FastAPI's
`TestClient`. No network calls, no live API keys.

```bash
cd ghostnet
pip install -r backend/requirements-dev.txt
# PYTHONPATH must include the repo root so `backend` is importable
PYTHONPATH=. pytest            # Linux/macOS
$env:PYTHONPATH="."; pytest    # Windows PowerShell
```

Layout (`backend/tests/`):
- `conftest.py` — `make_client` fixture (mock-transport AsyncClient factory)
- `test_schemas.py` — Pydantic boundary contract
- `test_risk_engine.py` — scoring ladder + report aggregation robustness
- `test_orchestrator.py` — pipeline routing, event streaming, failure isolation
- `test_modules.py` — every module's parsing/findings + interface contract
- `test_api.py` — `/health` and `/ws/recon` framing

## Testing Targets (Safe & Legal)

| Target | Type | Why |
|---|---|---|
| `example.com` | domain | IANA reference domain |
| `github.com` | domain | Large attack surface, good CT data |
| `testphp.vulnweb.com` | domain | Intentionally vulnerable (Acunetix) |
| `1.1.1.1` | ip | Cloudflare DNS — known clean |
| `8.8.8.8` | ip | Google DNS — known clean |
| `scanme.nmap.org` | domain | Nmap official scan-me host |

**Only scan targets you own or have explicit permission to test.**

---

## Adding a New Module

1. Create `backend/modules/{name}_module.py` with `async def run(target, client) -> dict`
2. Add module name to `PIPELINE` dict in `orchestrator.py`
3. Add sidebar entry in `frontend/index.html` with id `mod-{name}`
4. Module dot and counter will auto-wire via existing JS state management

---

## Environment Variables

```bash
# .env — all optional, enhances specific modules
ABUSEIPDB_KEY=          # rep_module: IP abuse score (1000 checks/day free)
VIRUSTOTAL_KEY=         # future: domain/hash reputation
SHODAN_KEY=             # future: banner/port intel
```

---

## Known Limitations

- HackerTarget free tier: 5 API calls/day per IP — nmap module may hit limit
- crt.sh: occasional 503 under load — handled with graceful fallback
- ip-api.com: 45 requests/minute — sufficient for single scans
- OTX: no key needed but rate-limited at ~100 req/min
- Email module: HIBP requires paid key for email-level lookup; domain-level is free

---

## Roadmap

- [ ] Email module: HIBP domain search, MX validation, permutation generator
- [ ] Entity graph: D3.js force layout linking discovered subdomains/IPs
- [ ] Session history: SQLite persistence for past scans
- [ ] PDF export: client-side jsPDF report generation
- [ ] Shodan-lite via HackerTarget banner grab
- [ ] Username enumeration module (Sherlock-style, async)
- [ ] WAF/CDN detection module
- [ ] Diff mode: compare two scans of same target over time

