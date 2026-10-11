"""Mocked network only: the client never assumes a third-party API or exports lab IPs."""

import httpx
import pytest

from src.tools.intel_clients import HTTPSIntel, IntelArgs


def test_https_intel_contract_and_private_non_export(monkeypatch):
    monkeypatch.setenv("ALLOW_EXTERNAL_INTEL", "yes")
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            json={
                "ip": request.url.params["ip"],
                "source": "unit-test",
                "reputation": "unknown",
                "confidence": 0.0,
            },
        )

    client = HTTPSIntel("https://intel.example", "intel.example", httpx.MockTransport(handler))
    assert client.lookup(IntelArgs(ip="172.30.0.10"))["source"] == "private_address_not_exported"
    assert not calls
    assert client.lookup(IntelArgs(ip="8.8.8.8"))["ip"] == "8.8.8.8"
    assert calls[0].method == "GET"


def test_intel_opt_in_and_destination(monkeypatch):
    monkeypatch.delenv("ALLOW_EXTERNAL_INTEL", raising=False)
    with pytest.raises(PermissionError):
        HTTPSIntel("https://intel.example", "intel.example")
    with pytest.raises(ValueError):
        HTTPSIntel("https://other.example", "intel.example")


def test_intel_size_cap(monkeypatch):
    monkeypatch.setenv("ALLOW_EXTERNAL_INTEL", "yes")
    client = HTTPSIntel(
        "https://intel.example",
        "intel.example",
        httpx.MockTransport(lambda request: httpx.Response(200, content=b"x" * 20000)),
    )
    with pytest.raises(ValueError, match="cap"):
        client.lookup(IntelArgs(ip="8.8.8.8"))
