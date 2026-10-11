"""Normalized sensor observations; content is untrusted evidence."""

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, field_validator


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: str = ""
    timestamp: datetime
    source: Literal["zeek", "suricata", "fixture", "ml"]
    kind: str = Field(max_length=64)
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(default=0, ge=0, le=65535)
    dst_port: int = Field(default=0, ge=0, le=65535)
    uid: str | None = None
    fields: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp")
    @classmethod
    def utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("timezone required")
        return value.astimezone(UTC)

    def identified(self) -> "Event":
        payload = self.model_dump(mode="json", exclude={"evidence_id", "uid"})
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
        return self.model_copy(update={"evidence_id": digest})
