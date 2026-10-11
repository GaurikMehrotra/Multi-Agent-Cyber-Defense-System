"""Authorization, rate/size limits, human approvals and simulator collateral."""

import hashlib

import pytest
from fastapi.testclient import TestClient

from src.agents.approvals import Approvals
from src.agents.killswitch import KillSwitch
from src.api.main import create_app
from src.api.worker import process_one
from src.db.audit import Audit
from src.response.plans import Plan
from src.response.simulator import Host, Simulator

ADMIN = {"X-API-Key": "test-admin"}
VIEWER = {"X-API-Key": "test-viewer"}


def test_auth_rbac_pagination_size(client, obs):
    assert client.get("/events").status_code == 401
    assert client.post("/events", json=obs[0], headers=VIEWER).status_code == 403
    assert client.post("/events", json=obs[0], headers=ADMIN).status_code == 200
    assert client.get("/events?limit=101", headers=ADMIN).status_code == 422
    assert client.post("/events", content="x" * 70000, headers=ADMIN).status_code == 413
    assert client.get("/openapi.json").status_code == 401
    assert client.get("/openapi.json", headers=ADMIN).status_code == 200


def test_rate_limit(factory, tmp_path):
    records = [
        {"hash": hashlib.sha256(b"test-admin").hexdigest(), "role": "admin", "actor": "human"}
    ]
    with TestClient(create_app(factory, records, tmp_path, rate_limit=2)) as client:
        assert client.get("/events", headers=ADMIN).status_code == 200
        assert client.get("/events", headers=ADMIN).status_code == 200
        assert client.get("/events", headers=ADMIN).status_code == 429


def test_end_to_end_worker_approval(client, factory, tmp_path, obs, monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "fake")
    monkeypatch.setenv("VERIFY_MODE", "mock")
    inserted = client.post("/events", json=obs[0], headers=ADMIN).json()
    response = client.post(
        "/cases",
        json={"ip": "172.30.0.10", "evidence_ids": [inserted["evidence_id"]]},
        headers=ADMIN,
    )
    assert response.status_code == 200
    case_id = response.json()["id"]
    assert client.post(f"/cases/{case_id}/approve", headers=ADMIN).status_code == 409
    assert process_one(factory, str(tmp_path))
    case = client.get(f"/cases/{case_id}", headers=ADMIN).json()
    assert case["status"] == "awaiting_approval"
    assert case["report"]["report"]["decision"] == "escalate"
    assert client.post(f"/cases/{case_id}/approve", headers=VIEWER).status_code == 403
    result = client.post(f"/cases/{case_id}/approve", headers=ADMIN)
    assert result.status_code == 200 and result.json()["simulated"]
    assert client.get("/network", headers=ADMIN).json()["assets"]


def test_kill_switch(client, obs):
    assert client.post("/stop", headers=VIEWER).status_code == 403
    assert client.post("/stop", headers=ADMIN).status_code == 200
    assert client.post("/events", json=obs[0], headers=ADMIN).status_code == 423
    assert client.post("/resume", headers=ADMIN).status_code == 200
    assert client.post("/events", json=obs[0], headers=ADMIN).status_code == 200


def test_simulator_exact_approval_and_collateral(factory, tmp_path):
    audit = Audit(tmp_path / "audit")
    approvals = Approvals(factory, audit)
    kill = KillSwitch(tmp_path / "STOP")
    simulator = Simulator(
        [
            Host(entity="bad", malicious=True),
            Host(entity="critical", malicious=False, criticality=5, dependencies=["bad"]),
        ],
        kill,
        audit,
    )
    plan = Plan(action="quarantine_host", entity="bad", evidence_ids=["known"], confidence=0.9)
    with pytest.raises(PermissionError):
        simulator.apply("case", plan, approvals)
    approvals.grant("case", plan, "human-owner")
    changed = plan.model_copy(update={"action": "block_ip"})
    with pytest.raises(PermissionError):
        simulator.apply("case", changed, approvals)
    result = simulator.apply("case", plan, approvals)
    assert result["malicious_contained"] == 1 and result["activity_stopped"]
    assert result["collateral_damage"] == 5
    kill.stop()
    with pytest.raises(RuntimeError):
        simulator.apply("case", plan, approvals)


def test_unknown_evidence_case(client):
    assert (
        client.post(
            "/cases", headers=ADMIN, json={"ip": "172.30.0.10", "evidence_ids": ["unknown"]}
        ).status_code
        == 422
    )


def test_interrupted_worker_has_termination_reason(factory):
    from src.api.worker import recover_interrupted
    from src.db.models import Case

    with factory() as session:
        session.add(Case(id="interrupted", status="running", payload={"ip": "172.30.0.10"}))
        session.commit()
    assert recover_interrupted(factory) == 1
    with factory() as session:
        row = session.get(Case, "interrupted")
        assert row.status == "failed"
        assert row.report["termination"] == "worker_restart_interrupted"


def test_unknown_ground_truth_never_claims_response_quality(tmp_path):
    simulator = Simulator(
        [Host(entity="unknown")], KillSwitch(tmp_path / "STOP"), Audit(tmp_path / "audit")
    )
    score = simulator.score()
    assert score["response_quality_available"] is False
    assert score["unknown_ground_truth_entities"] == ["unknown"]
    assert score["collateral_damage"] is None and score["activity_stopped"] is None


def test_worker_configuration_failure_finishes_case(client, factory, tmp_path, obs, monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "invalid-provider")
    inserted = client.post("/events", json=obs[0], headers=ADMIN).json()
    case_id = client.post(
        "/cases",
        json={"ip": "172.30.0.10", "evidence_ids": [inserted["evidence_id"]]},
        headers=ADMIN,
    ).json()["id"]
    assert process_one(factory, str(tmp_path))
    case = client.get(f"/cases/{case_id}", headers=ADMIN).json()
    assert case["status"] == "failed"
    assert case["report"]["termination"] == "worker_failure"
