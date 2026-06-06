from __future__ import annotations

import httpx

OTX_BASE = "https://otx.alienvault.com/api/v1/indicators"


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    try:
        import ipaddress
        try:
            addr = ipaddress.ip_address(target)
            indicator_type = "IPv6" if isinstance(addr, ipaddress.IPv6Address) else "IPv4"
        except ValueError:
            indicator_type = "domain"

        sections = ["general", "reputation"]
        for section in sections:
            try:
                r = await client.get(f"{OTX_BASE}/{indicator_type}/{target}/{section}")
                r.raise_for_status()
                data[section] = r.json()
            except (httpx.HTTPError, ValueError, Exception):
                data[section] = {}

        general = data.get("general", {})
        pulse_count = general.get("pulse_info", {}).get("count", 0)
        data["pulse_count"] = pulse_count

        malware_families: list[str] = []
        for pulse in general.get("pulse_info", {}).get("pulses", []):
            for tag in pulse.get("tags", []):
                malware_families.append(tag)
        data["malware_families"] = list(set(malware_families))

        if pulse_count > 0:
            findings.append({
                "severity": "CRITICAL",
                "title": f"Known threat actor — {pulse_count} OTX pulse(s)",
                "detail": f"AlienVault OTX has {pulse_count} threat intelligence pulses for {target}",
            })

        if malware_families:
            findings.append({
                "severity": "HIGH",
                "title": f"Malware associations: {', '.join(malware_families[:5])}",
                "detail": f"Target linked to malware families in OTX threat data",
            })

        reputation = data.get("reputation", {})
        rep_score = reputation.get("reputation", {}).get("score", None)
        data["reputation_score"] = rep_score
        if rep_score is not None and rep_score < 0:
            findings.append({
                "severity": "HIGH",
                "title": f"Negative reputation score: {rep_score}",
                "detail": "OTX reputation engine flagged this indicator",
            })

    except (httpx.HTTPError, ValueError, Exception) as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "otx", "data": data, "findings": findings}
