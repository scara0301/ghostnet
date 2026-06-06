from __future__ import annotations

import httpx


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    try:
        fields = "status,country,countryCode,region,regionName,city,org,as,proxy,hosting,query"
        r = await client.get(f"http://ip-api.com/json/{target}", params={"fields": fields})
        r.raise_for_status()
        geo = r.json()

        if geo.get("status") != "success":
            return {"module": "geo", "data": {"error": geo.get("message", "lookup failed")}, "findings": []}

        data = {k: geo.get(k) for k in ("country", "countryCode", "region", "regionName", "city", "org", "as", "proxy", "hosting", "query")}

        if geo.get("proxy"):
            findings.append({
                "severity": "HIGH",
                "title": "IP flagged as proxy/VPN",
                "detail": f"{target} is identified as a proxy or VPN exit node by ip-api.com",
            })

        if geo.get("hosting"):
            findings.append({
                "severity": "MEDIUM",
                "title": "IP belongs to hosting provider",
                "detail": f"ASN: {geo.get('as')} — datacenter/hosting IP",
            })

    except (httpx.HTTPError, ValueError, Exception) as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "geo", "data": data, "findings": findings}
