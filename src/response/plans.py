"""Plans are proposals, not executable infrastructure commands."""

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Plan(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: Literal["observe", "escalate", "block_ip", "quarantine_host", "disable_account"]
    entity: str = Field(min_length=1, max_length=100)
    evidence_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)

    def digest(self):
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True).encode()).hexdigest()
