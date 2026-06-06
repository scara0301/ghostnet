from __future__ import annotations

import httpx

DOH = "https://dns.google/resolve"
RECORD_TYPES = ["A", "MX", "TXT", "NS", "AAAA"]


async def _query(client: httpx.AsyncClient, name: str, rtype: str) -> list[dict]:
    try:
        r = await client.get(DOH, params={"name": name, "type": rtype})
        r.raise_for_status()
        return r.json().get("Answer", [])
    except (httpx.HTTPError, ValueError, Exception):
        return []


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    # Accept an email target by operating on its domain part.
    domain = target.split("@")[-1] if "@" in target else target

    try:
        for rtype in RECORD_TYPES:
            records = await _query(client, domain, rtype)
            data[rtype] = [rec.get("data", "") for rec in records]

        txt_records = " ".join(data.get("TXT", []))

        if not data.get("MX"):
            findings.append({
                "severity": "MEDIUM",
                "title": "No MX records",
                "detail": "Domain has no mail exchange records configured",
            })

        if "v=spf1" not in txt_records:
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing SPF record",
                "detail": "No SPF TXT record found — domain vulnerable to email spoofing",
            })

        dmarc = await _query(client, f"_dmarc.{domain}", "TXT")
        data["DMARC"] = [rec.get("data", "") for rec in dmarc]
        if not dmarc:
            findings.append({
                "severity": "MEDIUM",
                "title": "Missing DMARC record",
                "detail": "No DMARC policy found at _dmarc." + domain,
            })

    except (httpx.HTTPError, ValueError, Exception) as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "dns", "data": data, "findings": findings}
