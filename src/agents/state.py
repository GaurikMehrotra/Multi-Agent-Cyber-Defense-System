"""Serializable graph state contains evidence and proposals, never authorization."""

from typing import TypedDict


class State(TypedDict, total=False):
    run_id: str
    ip: str
    evidence: dict
    trace: list[dict]
    report: dict
    plan: dict
    error: str
    termination: str
