from __future__ import annotations

import httpx

SENSITIVE_KEYWORDS = {"admin", "vpn", "dev", "staging", "test", "internal", "api", "mail", "ftp"}


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    try:
        r = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{target}", "output": "json"},
            timeout=30.0,
        )
        r.raise_for_status()
        entries = r.json()

        subdomains: set[str] = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line and line != target:
                    subdomains.add(line)

        data["subdomains"] = sorted(subdomains)
        data["count"] = len(subdomains)

        sensitive = [s for s in subdomains if any(kw in s.split(".")[0] for kw in SENSITIVE_KEYWORDS)]
        data["sensitive"] = sensitive

        for sub in sensitive:
            findings.append({
                "severity": "MEDIUM",
                "title": f"Sensitive subdomain exposed: {sub}",
                "detail": f"Certificate transparency log reveals {sub}",
            })

        if len(subdomains) > 50:
            findings.append({
                "severity": "INFO",
                "title": f"Large subdomain footprint ({len(subdomains)} entries)",
                "detail": "Large number of subdomains increases attack surface",
            })

    except (httpx.HTTPError, ValueError, Exception) as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "crt", "data": data, "findings": findings}
