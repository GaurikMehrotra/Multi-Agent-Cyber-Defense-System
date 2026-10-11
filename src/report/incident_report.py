"""Schema-validated hypotheses. Grounding verifies references, not truth of prose."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class Claim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    hypothesis: str = Field(min_length=1, max_length=1000)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(min_length=1, max_length=20)
    technique_id: str | None = None


class IncidentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    claims: list[Claim] = Field(max_length=20)
    decision: Literal["observe", "escalate", "propose_containment"]
    model: str = Field(max_length=200)
    termination: str = Field(max_length=200)


def validate(report: IncidentReport, evidence: dict, attack_ids: set[str], confidence_gate=0.8):
    for claim in report.claims:
        if not set(claim.evidence_ids).issubset(evidence):
            raise ValueError("unsupported evidence reference")
        if claim.technique_id and claim.technique_id not in attack_ids:
            raise ValueError("unknown ATT&CK technique")
        if claim.confidence < confidence_gate and report.decision != "escalate":
            raise ValueError("low confidence must escalate")
    if not report.claims and report.decision != "escalate":
        raise ValueError("empty report must escalate")
    return report
