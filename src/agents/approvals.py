"""Approval is bound to an exact plan digest and recorded by an authenticated human."""

from sqlalchemy import select

from src.db.models import Approval


class Approvals:
    def __init__(self, session_factory, audit):
        self.sessions, self.audit = session_factory, audit

    def grant(self, case_id, plan, actor):
        if not actor or actor.startswith("agent:"):
            raise PermissionError("authenticated human required")
        with self.sessions() as session:
            existing = session.scalar(
                select(Approval).where(
                    Approval.case_id == case_id, Approval.plan_hash == plan.digest()
                )
            )
            if not existing:
                session.add(Approval(case_id=case_id, plan_hash=plan.digest(), actor=actor))
                session.commit()
        self.audit.write(case_id, "approval", {"actor": actor, "plan_hash": plan.digest()})

    def check(self, case_id, plan):
        with self.sessions() as session:
            row = session.scalar(
                select(Approval).where(
                    Approval.case_id == case_id, Approval.plan_hash == plan.digest()
                )
            )
            if not row:
                raise PermissionError("human approval required for exact plan")
