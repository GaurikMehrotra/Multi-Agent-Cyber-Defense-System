"""Offline mock enrichment is explicitly not real threat intelligence."""

import os
from typing import Literal
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress


class IntelArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: IPvAnyAddress


class MockIntel:
    def lookup(self, args: IntelArgs):
        return {
            "ip": str(args.ip),
            "source": "offline_mock",
            "reputation": "unknown",
            "confidence": 0.0,
        }


class IntelResult(BaseModel):
    """Custom operator-owned service contract; not an assumed vendor API."""

    model_config = ConfigDict(extra="forbid")
    ip: IPvAnyAddress
    source: str = Field(min_length=1, max_length=200)
    reputation: Literal["unknown", "benign", "suspicious"]
    confidence: float = Field(ge=0, le=1)


class HTTPSIntel:
    """Bounded read-only GET /lookup?ip=... against an explicitly approved host."""

    def __init__(self, base_url: str, allowed_hostname: str, transport=None):
        parsed = urlparse(base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != allowed_hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("approved HTTPS intel endpoint required")
        if os.getenv("ALLOW_EXTERNAL_INTEL") != "yes":
            raise PermissionError("external intel export requires explicit owner opt-in")
        self.url = base_url.rstrip("/") + "/lookup"
        self.transport = transport
        self.key = os.getenv("INTEL_API_KEY")

    def lookup(self, args: IntelArgs) -> dict:
        if not args.ip.is_global:
            return {
                "ip": str(args.ip),
                "source": "private_address_not_exported",
                "reputation": "unknown",
                "confidence": 0.0,
            }
        headers = {"X-API-Key": self.key} if self.key else {}
        with httpx.Client(transport=self.transport, timeout=3, follow_redirects=False) as client:
            with client.stream(
                "GET", self.url, params={"ip": str(args.ip)}, headers=headers
            ) as response:
                response.raise_for_status()
                content = bytearray()
                for chunk in response.iter_bytes():
                    content.extend(chunk)
                    if len(content) > 16384:
                        raise ValueError("intel response exceeds cap")
        result = IntelResult.model_validate_json(content)
        if result.ip != args.ip:
            raise ValueError("intel response entity mismatch")
        return result.model_dump(mode="json")
