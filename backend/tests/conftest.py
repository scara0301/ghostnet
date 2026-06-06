"""Shared fixtures for the GHOSTNET test suite.

Modules talk to the network exclusively through the ``httpx.AsyncClient`` handed
to them by the orchestrator. We exploit that contract by injecting an
``httpx.MockTransport``-backed client so every module can be exercised fully
offline, deterministically, with no live API calls.
"""
from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest_asyncio


@pytest_asyncio.fixture
async def make_client() -> Callable[[Callable[[httpx.Request], httpx.Response]], httpx.AsyncClient]:
    """Return a factory that builds an AsyncClient driven by a mock handler.

    Usage::

        async def test_x(make_client):
            client = make_client(lambda req: httpx.Response(200, json={...}))
            result = await some_module.run("example.com", client)
    """
    created: list[httpx.AsyncClient] = []

    def _make(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.AsyncClient:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        created.append(client)
        return client

    yield _make

    for client in created:
        await client.aclose()


def json_response(payload: object, status: int = 200) -> httpx.Response:
    """Convenience builder for a JSON mock response."""
    return httpx.Response(status, json=payload)


def text_response(body: str, status: int = 200) -> httpx.Response:
    """Convenience builder for a plain-text mock response."""
    return httpx.Response(status, text=body)
