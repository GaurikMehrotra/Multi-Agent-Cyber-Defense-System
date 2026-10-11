"""Authenticated, bounded single-process development API; all actions are simulated."""

import hashlib
import hmac
import json
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress
from sqlalchemy import select, text

from src.agents.approvals import Approvals
from src.agents.killswitch import KillSwitch
from src.db.audit import Audit
from src.db.models import Case, Observation
from src.events.schema import Event
from src.events.store import ingest, sessions
from src.response.plans import Plan
from src.response.simulator import Host, Simulator


class CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: IPvAnyAddress
    evidence_ids: list[str] = Field(min_length=1, max_length=100)


class Override(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan: Plan
    reason: str = Field(min_length=10, max_length=1000)


class SizeLimit:
    def __init__(self, app, limit=65536):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        chunks, size = [], 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > self.limit:
                await send({"type": "http.response.start", "status": 413, "headers": []})
                await send({"type": "http.response.body", "body": b"request too large"})
                return
            chunks.append(message)
            if not message.get("more_body", False):
                break

        async def replay():
            return chunks.pop(0) if chunks else await receive()

        await self.app(scope, replay, send)


def create_app(session_factory=None, key_records=None, runtime_dir="runtime", rate_limit=60):
    session_factory = session_factory or sessions()
    runtime_path = Path(runtime_dir)
    audit = Audit(runtime_path / "audit.jsonl", session_factory)
    kill = KillSwitch(runtime_path / "STOP")
    approvals = Approvals(session_factory, audit)
    keys = key_records if key_records is not None else json.loads(os.environ["API_KEY_RECORDS"])
    if not keys or any(
        record.get("role") not in {"viewer", "analyst", "admin"}
        or len(record.get("hash", "")) != 64
        for record in keys
    ):
        raise ValueError("nonempty hashed API key records required")
    hits = defaultdict(deque)
    rate_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        with session_factory() as session:
            session.execute(text("SELECT 1"))
        yield

    app = FastAPI(title="Defensive Lab SOC", version="0.1.0", lifespan=lifespan)
    app.add_middleware(SizeLimit)

    def auth(x_api_key: str = Header(default="")):
        digest = hashlib.sha256(x_api_key.encode()).hexdigest()
        record = next((entry for entry in keys if hmac.compare_digest(entry["hash"], digest)), None)
        if record is None:
            raise HTTPException(401, "invalid API key")
        now = time.monotonic()
        with rate_lock:
            window = hits[digest]
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= rate_limit:
                raise HTTPException(429, "rate limit exceeded")
            window.append(now)
        return record

    def access(record, roles):
        if record["role"] not in roles:
            raise HTTPException(403, "role denied")

    def active():
        try:
            kill.check()
        except RuntimeError as exc:
            raise HTTPException(423, str(exc)) from exc

    def case_get(session, case_id, lock=False):
        case = (
            session.scalar(select(Case).where(Case.id == case_id).with_for_update())
            if lock
            else session.get(Case, case_id)
        )
        if case is None:
            raise HTTPException(404, "case missing")
        return case

    @app.get("/health")
    def health():
        with session_factory() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ok", "stopped": kill.path.exists()}

    @app.post("/events")
    def add_event(event: Event, user=Depends(auth)):
        access(user, {"analyst", "admin"})
        active()
        with session_factory() as session:
            added = ingest(session, event)
        return {"inserted": added, "evidence_id": event.identified().evidence_id}

    @app.get("/events")
    def events(
        offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100), user=Depends(auth)
    ):
        with session_factory() as session:
            rows = session.scalars(
                select(Observation)
                .order_by(Observation.timestamp, Observation.evidence_id)
                .offset(offset)
                .limit(limit)
            )
            return [row.payload for row in rows]

    @app.post("/cases")
    def enqueue(body: CaseInput, user=Depends(auth)):
        access(user, {"analyst", "admin"})
        active()
        with session_factory() as session:
            rows = list(
                session.scalars(
                    select(Observation).where(Observation.evidence_id.in_(body.evidence_ids))
                )
            )
            if len(rows) != len(set(body.evidence_ids)):
                raise HTTPException(422, "unknown evidence")
            if any(str(body.ip) not in {row.src_ip, row.dst_ip} for row in rows):
                raise HTTPException(422, "evidence does not reference entity")
            case_id = str(uuid.uuid4())
            session.add(Case(id=case_id, status="queued", payload=body.model_dump(mode="json")))
            session.commit()
        audit.write(case_id, "case_created", {"actor": user["actor"]})
        return {"id": case_id}

    @app.get("/cases")
    def cases(
        offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100), user=Depends(auth)
    ):
        with session_factory() as session:
            return [
                {"id": row.id, "status": row.status}
                for row in session.scalars(
                    select(Case).order_by(Case.id).offset(offset).limit(limit)
                )
            ]

    @app.get("/cases/{case_id}")
    def case(case_id: str, user=Depends(auth)):
        with session_factory() as session:
            row = case_get(session, case_id)
            return {
                "id": row.id,
                "status": row.status,
                "payload": row.payload,
                "report": row.report,
            }

    @app.post("/cases/{case_id}/override")
    def override(case_id: str, body: Override, user=Depends(auth)):
        access(user, {"admin"})
        active()
        with session_factory() as session:
            row = case_get(session, case_id, lock=True)
            if row.status != "awaiting_approval" or not row.report:
                raise HTTPException(409, "case not awaiting approval")
            evidence = row.report.get("evidence", {})
            if (
                not set(body.plan.evidence_ids).issubset(evidence)
                or body.plan.entity != row.payload["ip"]
            ):
                raise HTTPException(422, "override requires case entity and known evidence")
            if body.plan.confidence < 0.8 and body.plan.action not in {"observe", "escalate"}:
                raise HTTPException(422, "low confidence must escalate")
            row.report = {**row.report, "plan": body.plan.model_dump()}
            session.commit()
        audit.write(
            case_id,
            "override",
            {"actor": user["actor"], "reason": body.reason, "plan": body.plan.model_dump()},
        )
        return {"status": "proposal_changed_approval_required"}

    @app.post("/cases/{case_id}/approve")
    def approve(case_id: str, user=Depends(auth)):
        access(user, {"admin"})
        active()
        with session_factory() as session:
            row = case_get(session, case_id, lock=True)
            if row.status != "awaiting_approval" or not row.report or not row.report.get("plan"):
                raise HTTPException(409, "case not awaiting approval")
            plan = Plan.model_validate(row.report["plan"])
            approvals.grant(case_id, plan, user["actor"])
            hosts = [Host(entity=row.payload["ip"], services=["lab-http"], criticality=3)]
            result = Simulator(hosts, kill, audit).apply(case_id, plan, approvals)
            row.report = {**row.report, "simulation": result}
            row.status = "simulated"
            session.commit()
        return {"simulated": True, "score": result}

    @app.get("/network")
    def network(user=Depends(auth)):
        with session_factory() as session:
            cases = list(session.scalars(select(Case).where(Case.status == "simulated").limit(100)))
            return {
                "simulated": True,
                "assets": [
                    {
                        "entity": row.payload["ip"],
                        "case": row.id,
                        "result": row.report["simulation"],
                    }
                    for row in cases
                ],
            }

    @app.post("/stop")
    def stop(user=Depends(auth)):
        access(user, {"admin"})
        kill.stop()
        audit.write("global", "kill_switch", {"actor": user["actor"]})
        return {"stopped": True}

    @app.post("/resume")
    def resume(user=Depends(auth)):
        access(user, {"admin"})
        audit.write("global", "kill_switch_override", {"actor": user["actor"]})
        kill.path.unlink(missing_ok=True)
        return {"stopped": False}

    # Protect interactive API documentation too.
    @app.middleware("http")
    async def docs_auth(request: Request, call_next):
        if request.url.path in {"/docs", "/redoc", "/openapi.json"}:
            try:
                auth(request.headers.get("x-api-key", ""))
            except HTTPException as exc:
                from fastapi.responses import JSONResponse

                return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return await call_next(request)

    return app
