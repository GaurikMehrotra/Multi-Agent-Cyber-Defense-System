"""Parameterized persistence and deduplication by content-addressed evidence ID."""

import os

from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from src.db.models import Observation
from src.events.schema import Event


def sessions(url: str | None = None):
    engine = create_engine(url or os.environ["DATABASE_URL"], pool_pre_ping=True)
    return sessionmaker(engine, expire_on_commit=False)


def ingest(session, event: Event) -> bool:
    event = event.identified()
    if session.get(Observation, event.evidence_id):
        return False
    session.add(
        Observation(
            evidence_id=event.evidence_id,
            timestamp=event.timestamp,
            source=event.source,
            kind=event.kind,
            src_ip=str(event.src_ip),
            dst_ip=str(event.dst_ip),
            payload=event.model_dump(mode="json"),
        )
    )
    try:
        session.commit()
    except IntegrityError:
        session.rollback()
        return False
    return True


def query(session, ip: str, limit: int = 100, start=None, end=None) -> list[dict]:
    if not 1 <= limit <= 100:
        raise ValueError("row limit must be 1..100")
    stmt = (
        select(Observation)
        .where((Observation.src_ip == ip) | (Observation.dst_ip == ip))
        .order_by(Observation.timestamp)
        .limit(limit)
    )
    if (start is None) != (end is None):
        raise ValueError("both time boundaries required")
    if start is not None:
        if start > end or (end - start).total_seconds() > 3600:
            raise ValueError("invalid or excessive query window")
        stmt = stmt.where(Observation.timestamp >= start, Observation.timestamp <= end)
    return [row.payload for row in session.scalars(stmt)]
