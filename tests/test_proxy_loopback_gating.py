"""Loopback-gating tests for state-mutating / content-leaking endpoints.

``/transformations/feed`` can return full prompt + completion bodies (when
``log_full_messages`` is on) and ``/cache/clear`` mutates server state. With the
default ``--host 0.0.0.0`` Docker bind, neither should be reachable by an
arbitrary network client — they are gated to the loopback interface via
``require_loopback`` (the same guard already used for ``/admin/*`` and
``/debug/*``). See #863.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from headroom.proxy.server import ProxyConfig, create_app

GATED = [
    ("get", "/transformations/feed"),
    ("post", "/cache/clear"),
]


def _make_app() -> FastAPI:
    return create_app(
        ProxyConfig(
            optimize=False,
            cache_enabled=False,
            rate_limit_enabled=False,
            cost_tracking_enabled=False,
            log_requests=False,
            ccr_inject_tool=False,
            ccr_handle_responses=False,
            ccr_context_tracking=False,
            image_optimize=False,
        )
    )


def _loopback_client() -> TestClient:
    # A real loopback peer + a loopback Host header — passes both guard gates
    # (client-IP check and the DNS-rebinding Host-header check).
    return TestClient(_make_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 12345))


@pytest.mark.parametrize("method,path", GATED)
def test_non_loopback_caller_gets_404(method: str, path: str) -> None:
    # A vanilla TestClient presents client.host="testclient", which is not a
    # loopback IP, so the guard returns 404 (invisible, not 403).
    client = TestClient(_make_app())
    resp = client.request(method, path)
    assert resp.status_code == 404, resp.text


@pytest.mark.parametrize("method,path", GATED)
def test_loopback_caller_allowed(method: str, path: str) -> None:
    client = _loopback_client()
    resp = client.request(method, path)
    assert resp.status_code == 200, resp.text


def test_dns_rebinding_host_header_rejected() -> None:
    # Loopback peer IP but an attacker-controlled Host header (the DNS-rebinding
    # shape) must still be rejected by the second gate.
    client = TestClient(_make_app(), base_url="http://127.0.0.1", client=("127.0.0.1", 12345))
    resp = client.get("/transformations/feed", headers={"host": "attacker.example"})
    assert resp.status_code == 404, resp.text
