"""Portable SQLAlchemy models; PostgreSQL is the production development store."""

from sqlalchemy import JSON, DateTime, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Observation(Base):
    __tablename__ = "observations"
    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[object] = mapped_column(DateTime(timezone=True), index=True)
    source: Mapped[str] = mapped_column(String(16))
    kind: Mapped[str] = mapped_column(String(64))
    src_ip: Mapped[str] = mapped_column(String(45), index=True)
    dst_ip: Mapped[str] = mapped_column(String(45), index=True)
    payload: Mapped[dict] = mapped_column(JSON)


class Case(Base):
    __tablename__ = "cases"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    payload: Mapped[dict] = mapped_column(JSON)
    report: Mapped[dict | None] = mapped_column(JSON, nullable=True)


class AuditRow(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(String(64), index=True)
    kind: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    digest: Mapped[str] = mapped_column(String(64), unique=True)
    previous: Mapped[str] = mapped_column(String(64))


class Approval(Base):
    __tablename__ = "approvals"
    __table_args__ = (UniqueConstraint("case_id", "plan_hash"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[str] = mapped_column(String(64))
    plan_hash: Mapped[str] = mapped_column(String(64))
    actor: Mapped[str] = mapped_column(String(64))
