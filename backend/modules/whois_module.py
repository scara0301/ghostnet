from __future__ import annotations

from datetime import datetime, timezone

import httpx


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    # Accept an email target by operating on its domain part.
    domain = target.split("@")[-1] if "@" in target else target

    try:
        r = await client.get(f"https://rdap.org/domain/{domain}")
        r.raise_for_status()
        rdap = r.json()

        registrar = next(
            (e.get("vcardArray", [[]])[1] for e in rdap.get("entities", [])
             if "registrar" in e.get("roles", [])),
            None,
        )
        data["registrar"] = registrar

        expiry_str = next(
            (ev.get("eventDate") for ev in rdap.get("events", [])
             if ev.get("eventAction") == "expiration"),
            None,
        )
        data["expiry"] = expiry_str

        status = rdap.get("status", [])
        data["status"] = status

        if expiry_str:
            try:
                expiry_dt = datetime.fromisoformat(expiry_str.replace("Z", "+00:00"))
                days_left = (expiry_dt - datetime.now(timezone.utc)).days
                data["days_until_expiry"] = days_left
                if days_left < 30:
                    findings.append({
                        "severity": "HIGH",
                        "title": "Domain expiring soon",
                        "detail": f"Expires in {days_left} days ({expiry_str})",
                    })
            except ValueError:
                pass

        if "clientDeleteProhibited" not in status:
            findings.append({
                "severity": "LOW",
                "title": "clientDeleteProhibited not set",
                "detail": "Domain lacks delete-lock status flag",
            })

    except (httpx.HTTPError, ValueError, Exception) as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "whois", "data": data, "findings": findings}
