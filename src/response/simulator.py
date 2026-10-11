"""Mock-only containment with dependency-aware collateral scoring."""

from pydantic import BaseModel, Field

from src.response.plans import Plan


class Host(BaseModel):
    entity: str
    criticality: int = Field(default=1, ge=1, le=5)
    malicious: bool | None = None
    services: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    contained: bool = False


class Simulator:
    def __init__(self, hosts: list[Host], kill, audit):
        self.hosts = {host.entity: host.model_copy(deep=True) for host in hosts}
        self.kill, self.audit = kill, audit

    def apply(self, case_id: str, plan: Plan, approvals):
        self.kill.check()
        approvals.check(case_id, plan)
        if plan.entity not in self.hosts:
            raise ValueError("unknown simulated entity")
        if plan.confidence < 0.8 and plan.action not in {"observe", "escalate"}:
            raise ValueError("low confidence requires escalation")
        host = self.hosts[plan.entity]
        if plan.action not in {"observe", "escalate"}:
            host.contained = True
        self.audit.write(
            case_id, "simulated_response", {"plan": plan.model_dump(), "simulated": True}
        )
        return self.score()

    def score(self):
        blocked = {key for key, host in self.hosts.items() if host.contained}
        affected = set(blocked)
        while True:
            more = {key for key, host in self.hosts.items() if set(host.dependencies) & affected}
            if more <= affected:
                break
            affected |= more
        malicious = [host for host in self.hosts.values() if host.malicious is True]
        collateral = sum(
            host.criticality
            for key, host in self.hosts.items()
            if key in affected and host.malicious is False
        )
        unknown = [key for key, host in self.hosts.items() if host.malicious is None]
        return {
            "response_quality_available": not unknown,
            "unknown_ground_truth_entities": sorted(unknown),
            "malicious_contained": sum(host.contained for host in malicious)
            if not unknown
            else None,
            "malicious_total": len(malicious) if not unknown else None,
            "activity_stopped": (bool(malicious) and all(host.contained for host in malicious))
            if not unknown
            else None,
            "collateral_damage": collateral if not unknown else None,
            "affected_entities": sorted(affected),
        }
