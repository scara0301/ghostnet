from __future__ import annotations

import re

import httpx

DOH = "https://dns.google/resolve"
EMAIL_RE = re.compile(r"^[^@\s]+@([^@\s]+\.[^@\s]+)$")

# Common username permutation patterns for OSINT pivoting
_PERMUTATION_SUFFIXES = ["", ".admin", ".test", "1", "_admin", "+spam"]


async def _query_mx(client: httpx.AsyncClient, domain: str) -> list[str]:
    try:
        r = await client.get(DOH, params={"name": domain, "type": "MX"})
        r.raise_for_status()
        return [rec.get("data", "") for rec in r.json().get("Answer", [])]
    except (httpx.HTTPError, ValueError, Exception):
        return []


def _permutations(local: str, domain: str) -> list[str]:
    seen: list[str] = []
    for suffix in _PERMUTATION_SUFFIXES:
        candidate = f"{local}{suffix}@{domain}"
        if candidate not in seen:
            seen.append(candidate)
    return seen


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    try:
        match = EMAIL_RE.match(target.strip())
        if not match:
            findings.append({
                "severity": "INFO",
                "title": "Invalid email format",
                "detail": f"'{target}' is not a valid email address",
            })
            return {"module": "email", "data": {"valid": False}, "findings": findings}

        domain = match.group(1).lower()
        local = target.strip().split("@")[0]
        data["valid"] = True
        data["domain"] = domain
        data["local_part"] = local

        mx_records = await _query_mx(client, domain)
        data["mx"] = mx_records

        if not mx_records:
            findings.append({
                "severity": "HIGH",
                "title": "Email domain cannot receive mail",
                "detail": f"No MX records found for {domain} — address is likely undeliverable or spoofed",
            })

        data["permutations"] = _permutations(local, domain)

        # HIBP email-level lookup requires a paid key; domain-level breach search is free but
        # left as a documented pivot rather than a live call (see CLAUDE.md known limitations).
        findings.append({
            "severity": "INFO",
            "title": "HIBP domain-search pivot available",
            "detail": f"Check haveibeenpwned.com domain search for {domain} (email-level lookup needs a paid key)",
        })

    except (httpx.HTTPError, ValueError, Exception) as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "email", "data": data, "findings": findings}
