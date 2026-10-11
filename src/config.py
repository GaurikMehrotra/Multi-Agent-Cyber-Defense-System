"""Runtime configuration with explicit limits."""

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Budgets(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tools: int = Field(default=12, ge=0, le=100)
    scans: int = Field(default=1, ge=0, le=2)
    llm: int = Field(default=6, ge=0, le=30)
    seconds: float = Field(default=60, gt=0, le=300)


class Config(BaseModel):
    seed: int = 42
    threads: int = Field(default=2, ge=1, le=4)
    features: list[str]
    threshold: float = Field(default=0.5, ge=0, le=1)
    confidence_gate: float = Field(default=0.8, ge=0, le=1)
    budgets: Budgets = Budgets()
    limits: dict[str, int]
    models: dict[str, float]

    @field_validator("features")
    @classmethod
    def supported_features(cls, value):
        expected = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "dest_port"]
        if value != expected:
            raise ValueError("configured features must match the trained six-feature contract")
        return value


def load(path: str | Path = "configs/default.yaml") -> Config:
    return Config.model_validate(yaml.safe_load(Path(path).read_text()))
