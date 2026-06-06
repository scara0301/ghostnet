from __future__ import annotations

import httpx

DANGEROUS_PORTS = {21, 22, 23, 25, 445, 3389, 5900, 6379, 27017}
HT = "https://api.hackertarget.com"


async def _ht_get(client: httpx.AsyncClient, path: str, q: str) -> str:
    try:
        r = await client.get(f"{HT}/{path}/", params={"q": q}, timeout=30.0)
        r.raise_for_status()
        return r.text
    except httpx.HTTPError:
        return ""


async def run(target: str, client: httpx.AsyncClient) -> dict:
    findings: list[dict] = []
    data: dict = {}

    try:
        nmap_raw = await _ht_get(client, "nmap", target)
        hostsearch_raw = await _ht_get(client, "hostsearch", target)
        reversedns_raw = await _ht_get(client, "reversedns", target)

        data["nmap"] = nmap_raw
        data["hostsearch"] = hostsearch_raw
        data["reversedns"] = reversedns_raw

        open_ports: list[int] = []
        for line in nmap_raw.splitlines():
            parts = line.split()
            if len(parts) >= 2 and "/tcp" in parts[0] and "open" in parts[1]:
                try:
                    port = int(parts[0].split("/")[0])
                    open_ports.append(port)
                except ValueError:
                    pass

        data["open_ports"] = open_ports

        for port in open_ports:
            if port in DANGEROUS_PORTS:
                findings.append({
                    "severity": "HIGH",
                    "title": f"Dangerous port open: {port}",
                    "detail": f"Port {port}/tcp is open and associated with high-risk services",
                })

        if "error" in nmap_raw.lower() or "api calls" in nmap_raw.lower():
            findings.append({
                "severity": "INFO",
                "title": "HackerTarget rate limit reached",
                "detail": "Free tier limit (5 calls/day) may have been hit",
            })

    except Exception as exc:
        findings = []
        data = {"error": str(exc)}

    return {"module": "rep", "data": data, "findings": findings}
