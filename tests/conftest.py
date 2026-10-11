"""No real network, LLM, sensors or scans in tests."""

import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.api.main import create_app
from src.db.models import Base
from src.eval.scenarios import SCENARIOS, observations


@pytest.fixture
def factory():
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(engine, expire_on_commit=False)
    engine.dispose()


@pytest.fixture
def obs():
    return observations(SCENARIOS[0])


@pytest.fixture
def client(factory, tmp_path):
    records = [
        {"hash": hashlib.sha256(value.encode()).hexdigest(), "role": role, "actor": role}
        for value, role in [
            ("test-admin", "admin"),
            ("test-viewer", "viewer"),
            ("test-analyst", "analyst"),
        ]
    ]
    with TestClient(create_app(factory, records, tmp_path)) as client:
        yield client
