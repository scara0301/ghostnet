"""Per-module tests using httpx.MockTransport — fully offline.

Each module receives a mock-backed AsyncClient (via the ``make_client``
fixture), so we exercise real parsing/finding logic against canned API
responses and failure modes without touching the network.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import httpx
import pytest

from backend.modules import (
    crt_module,
    dns_module,
    email_module,
    geo_module,
    otx_module,
    rep_module,
    whois_module,
)

# --------------------------------------------------------------------------- #
# Interface contract — every module honours the same return shape.
# --------------------------------------------------------------------------- #

CONTRACT_CASES = [
    (whois_module, "whois", "example.com"),
    (dns_module, "dns", "example.com"),
    (crt_module, "crt", "example.com"),
    (geo_module, "geo", "1.1.1.1"),
    (rep_module, "rep", "1.1.1.1"),
    (otx_module, "otx", "1.1.1.1"),
    (email_module, "email", "user@example.com"),
]


@pytest.mark.parametrize("module,name,target", CONTRACT_CASES)
async def test_module_interface_contract(make_client, module, name, target):
    client = make_client(lambda req: httpx.Response(200, json={}))
    result = await module.run(target, client)
    assert set(result.keys()) >= {"module", "data", "findings"}
    assert result["module"] == name
    assert isinstance(result["data"], dict)
    assert isinstance(result["findings"], list)


@pytest.mark.parametrize("module,name,target", CONTRACT_CASES)
async def test_module_network_failure_is_graceful(make_client, module, name, target):
    """A total network failure must never crash a module — it returns the
    contract shape. Note dns/email isolate failures per-query (treating an
    unreachable resolver as "record absent"), so they may still emit findings;
    the guarantee tested here is "no exception, valid shape"."""
    def boom(req):
        raise httpx.ConnectError("network down", request=req)

    client = make_client(boom)
    result = await module.run(target, client)
    assert result["module"] == name
    assert isinstance(result["data"], dict)
    assert isinstance(result["findings"], list)


# Modules whose top-level handler resets findings to [] on a hard HTTP error.
RESET_ON_ERROR = [
    (whois_module, "whois", "example.com"),
    (crt_module, "crt", "example.com"),
    (geo_module, "geo", "1.1.1.1"),
    (otx_module, "otx", "1.1.1.1"),
    (rep_module, "rep", "1.1.1.1"),
]


@pytest.mark.parametrize("module,name,target", RESET_ON_ERROR)
async def test_module_http_error_returns_no_findings(make_client, module, name, target):
    client = make_client(lambda req: httpx.Response(500))
    result = await module.run(target, client)
    assert result["module"] == name
    assert result["findings"] == []


# --------------------------------------------------------------------------- #
# whois (RDAP)
# --------------------------------------------------------------------------- #

class TestWhois:
    async def test_expiry_soon_flags_high(self, make_client):
        soon = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
        payload = {
            "events": [{"eventAction": "expiration", "eventDate": soon}],
            "status": ["clientDeleteProhibited"],
            "entities": [],
        }
        client = make_client(lambda req: httpx.Response(200, json=payload))
        result = await whois_module.run("example.com", client)
        sevs = [f["severity"] for f in result["findings"]]
        assert "HIGH" in sevs

    async def test_missing_delete_lock_flags_low(self, make_client):
        payload = {"events": [], "status": [], "entities": []}
        client = make_client(lambda req: httpx.Response(200, json=payload))
        result = await whois_module.run("example.com", client)
        titles = [f["title"] for f in result["findings"]]
        assert any("clientDeleteProhibited" in t for t in titles)

    async def test_email_target_uses_domain_in_url(self, make_client):
        seen = {}

        def handler(req):
            seen["path"] = req.url.path
            return httpx.Response(200, json={"events": [], "status": ["clientDeleteProhibited"], "entities": []})

        client = make_client(handler)
        await whois_module.run("admin@example.com", client)
        assert seen["path"] == "/domain/example.com"

    async def test_http_error_returns_empty(self, make_client):
        client = make_client(lambda req: httpx.Response(500))
        result = await whois_module.run("example.com", client)
        assert result["findings"] == []
        assert "error" in result["data"]


# --------------------------------------------------------------------------- #
# dns (Google DoH)
# --------------------------------------------------------------------------- #

class TestDns:
    async def test_all_missing_flags_three_mediums(self, make_client):
        client = make_client(lambda req: httpx.Response(200, json={"Answer": []}))
        result = await dns_module.run("example.com", client)
        titles = {f["title"] for f in result["findings"]}
        assert {"No MX records", "Missing SPF record", "Missing DMARC record"} <= titles

    async def test_present_records_no_findings(self, make_client):
        def handler(req):
            name = req.url.params.get("name", "")
            rtype = req.url.params.get("type", "")
            if rtype == "MX":
                return httpx.Response(200, json={"Answer": [{"data": "10 mail.example.com."}]})
            if rtype == "TXT" and name.startswith("_dmarc."):
                return httpx.Response(200, json={"Answer": [{"data": "v=DMARC1; p=reject"}]})
            if rtype == "TXT":
                return httpx.Response(200, json={"Answer": [{"data": "v=spf1 -all"}]})
            return httpx.Response(200, json={"Answer": [{"data": "1.2.3.4"}]})

        client = make_client(handler)
        result = await dns_module.run("example.com", client)
        assert result["findings"] == []

    async def test_email_target_strips_to_domain(self, make_client):
        names = []

        def handler(req):
            names.append(req.url.params.get("name", ""))
            return httpx.Response(200, json={"Answer": []})

        client = make_client(handler)
        await dns_module.run("user@example.com", client)
        assert all("@" not in n for n in names)
        assert any(n == "example.com" for n in names)
        assert any(n == "_dmarc.example.com" for n in names)


# --------------------------------------------------------------------------- #
# crt (crt.sh)
# --------------------------------------------------------------------------- #

class TestCrt:
    async def test_sensitive_subdomain_flagged(self, make_client):
        entries = [
            {"name_value": "admin.example.com\nwww.example.com"},
            {"name_value": "*.example.com"},
        ]
        client = make_client(lambda req: httpx.Response(200, json=entries))
        result = await crt_module.run("example.com", client)
        assert result["data"]["count"] == 2
        sens_titles = [f["title"] for f in result["findings"] if f["severity"] == "MEDIUM"]
        assert any("admin.example.com" in t for t in sens_titles)

    async def test_large_footprint_flags_info(self, make_client):
        entries = [{"name_value": f"h{i}.example.com"} for i in range(60)]
        client = make_client(lambda req: httpx.Response(200, json=entries))
        result = await crt_module.run("example.com", client)
        assert result["data"]["count"] == 60
        assert any(f["severity"] == "INFO" for f in result["findings"])

    async def test_malformed_json_returns_empty(self, make_client):
        client = make_client(lambda req: httpx.Response(200, text="<html>503</html>"))
        result = await crt_module.run("example.com", client)
        assert result["findings"] == []
        assert "error" in result["data"]


# --------------------------------------------------------------------------- #
# geo (ip-api.com)
# --------------------------------------------------------------------------- #

class TestGeo:
    async def test_proxy_and_hosting_flagged(self, make_client):
        payload = {
            "status": "success", "country": "US", "as": "AS123",
            "proxy": True, "hosting": True, "query": "1.1.1.1",
        }
        client = make_client(lambda req: httpx.Response(200, json=payload))
        result = await geo_module.run("1.1.1.1", client)
        sevs = {f["severity"] for f in result["findings"]}
        assert {"HIGH", "MEDIUM"} <= sevs

    async def test_clean_ip_no_findings(self, make_client):
        payload = {"status": "success", "country": "US", "proxy": False, "hosting": False}
        client = make_client(lambda req: httpx.Response(200, json=payload))
        result = await geo_module.run("8.8.8.8", client)
        assert result["findings"] == []

    async def test_lookup_failure_status_returns_empty(self, make_client):
        payload = {"status": "fail", "message": "reserved range"}
        client = make_client(lambda req: httpx.Response(200, json=payload))
        result = await geo_module.run("10.0.0.1", client)
        assert result["findings"] == []
        assert "error" in result["data"]


# --------------------------------------------------------------------------- #
# rep (HackerTarget)
# --------------------------------------------------------------------------- #

class TestRep:
    async def test_dangerous_port_flagged(self, make_client):
        def handler(req):
            if req.url.path == "/nmap/":
                return httpx.Response(200, text="22/tcp open ssh\n80/tcp open http")
            return httpx.Response(200, text="")

        client = make_client(handler)
        result = await rep_module.run("1.1.1.1", client)
        assert 22 in result["data"]["open_ports"]
        highs = [f for f in result["findings"] if f["severity"] == "HIGH"]
        assert any("22" in f["title"] for f in highs)

    async def test_rate_limit_flags_info(self, make_client):
        def handler(req):
            if req.url.path == "/nmap/":
                return httpx.Response(200, text="API calls limit reached")
            return httpx.Response(200, text="")

        client = make_client(handler)
        result = await rep_module.run("1.1.1.1", client)
        assert any(f["severity"] == "INFO" for f in result["findings"])

    async def test_all_endpoints_down_no_findings(self, make_client):
        def handler(req):
            raise httpx.ConnectError("down", request=req)

        client = make_client(handler)
        result = await rep_module.run("1.1.1.1", client)
        assert result["findings"] == []
        assert result["data"]["open_ports"] == []


# --------------------------------------------------------------------------- #
# otx (AlienVault OTX)
# --------------------------------------------------------------------------- #

class TestOtx:
    async def test_pulses_and_malware_and_reputation(self, make_client):
        def handler(req):
            if req.url.path.endswith("/general"):
                return httpx.Response(200, json={
                    "pulse_info": {"count": 3, "pulses": [{"tags": ["apt28", "phishing"]}]},
                })
            if req.url.path.endswith("/reputation"):
                return httpx.Response(200, json={"reputation": {"score": -5}})
            return httpx.Response(200, json={})

        client = make_client(handler)
        result = await otx_module.run("8.8.8.8", client)
        sevs = [f["severity"] for f in result["findings"]]
        assert sevs.count("CRITICAL") == 1
        assert sevs.count("HIGH") == 2  # malware tags + negative reputation
        assert result["data"]["pulse_count"] == 3

    async def test_clean_indicator_no_findings(self, make_client):
        client = make_client(lambda req: httpx.Response(200, json={}))
        result = await otx_module.run("8.8.8.8", client)
        assert result["findings"] == []

    async def test_ipv4_indicator_type_in_url(self, make_client):
        seen = {}

        def handler(req):
            seen.setdefault("paths", []).append(req.url.path)
            return httpx.Response(200, json={})

        client = make_client(handler)
        await otx_module.run("8.8.8.8", client)
        assert all("/IPv4/" in p for p in seen["paths"])

    async def test_ipv6_indicator_type_in_url(self, make_client):
        seen = {}

        def handler(req):
            seen.setdefault("paths", []).append(req.url.path)
            return httpx.Response(200, json={})

        client = make_client(handler)
        await otx_module.run("2001:4860:4860::8888", client)
        assert all("/IPv6/" in p for p in seen["paths"])

    async def test_domain_indicator_type_in_url(self, make_client):
        seen = {}

        def handler(req):
            seen.setdefault("paths", []).append(req.url.path)
            return httpx.Response(200, json={})

        client = make_client(handler)
        await otx_module.run("example.com", client)
        assert all("/domain/" in p for p in seen["paths"])


# --------------------------------------------------------------------------- #
# email
# --------------------------------------------------------------------------- #

class TestEmail:
    async def test_valid_email_extracts_domain_and_permutations(self, make_client):
        client = make_client(lambda req: httpx.Response(200, json={"Answer": [{"data": "10 mx.example.com."}]}))
        result = await email_module.run("admin@example.com", client)
        assert result["data"]["valid"] is True
        assert result["data"]["domain"] == "example.com"
        assert result["data"]["local_part"] == "admin"
        assert len(result["data"]["permutations"]) == 6
        # Deliverable (MX present) → no HIGH, but HIBP INFO pivot present.
        assert not any(f["severity"] == "HIGH" for f in result["findings"])
        assert any("HIBP" in f["title"] for f in result["findings"])

    async def test_no_mx_flags_high(self, make_client):
        client = make_client(lambda req: httpx.Response(200, json={"Answer": []}))
        result = await email_module.run("admin@example.com", client)
        assert any(f["severity"] == "HIGH" for f in result["findings"])

    async def test_invalid_email_no_network_call(self, make_client):
        def handler(req):
            raise AssertionError("network should not be called for invalid email")

        client = make_client(handler)
        result = await email_module.run("not-an-email", client)
        assert result["data"]["valid"] is False
        assert any(f["title"] == "Invalid email format" for f in result["findings"])
