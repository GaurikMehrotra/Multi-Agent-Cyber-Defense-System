"""Canonical, numeric flow features; identifiers and labels never enter models."""

import hashlib
import json

import numpy as np
import pandas as pd

from src.events.schema import Event

FEATURES = ["duration", "orig_bytes", "resp_bytes", "orig_pkts", "resp_pkts", "dest_port"]
IDENTITY = ["timestamp", "src_ip", "dst_ip", "src_port", "dest_port", "protocol", *FEATURES[:-1]]


def from_conn(event: Event) -> dict:
    values = {name: float(event.fields.get(name) or 0) for name in FEATURES[:-1]}
    return {
        **values,
        "dest_port": event.dst_port,
        "src_port": event.src_port,
        "src_ip": str(event.src_ip),
        "dst_ip": str(event.dst_ip),
        "timestamp": event.timestamp.isoformat(),
        "protocol": event.fields.get("proto", "unknown"),
        "evidence_id": event.evidence_id,
    }


def canonical(frame: pd.DataFrame) -> pd.DataFrame:
    required = set(IDENTITY + ["label", "attack", "dataset"])
    if not required.issubset(frame.columns):
        raise ValueError(f"missing canonical columns: {sorted(required - set(frame.columns))}")
    frame = frame.copy()
    frame["timestamp"] = pd.to_datetime(frame.timestamp, utc=True)
    for name in FEATURES:
        frame[name] = pd.to_numeric(frame[name], errors="raise")
    if not np.isfinite(frame[FEATURES].to_numpy()).all() or (frame[FEATURES] < 0).any().any():
        raise ValueError("features must be finite and nonnegative")
    if not frame.label.isin([0, 1]).all():
        raise ValueError("binary label required")
    if ((frame.label == 0) != (frame.attack == "benign")).any():
        raise ValueError("inconsistent family and label")

    def fingerprint(row):
        values = {key: str(row[key]) for key in IDENTITY}
        return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()

    frame["flow_id"] = frame.apply(fingerprint, axis=1)
    conflicts = frame.groupby("flow_id").label.nunique()
    family_conflicts = frame.groupby("flow_id").attack.nunique()
    if (conflicts > 1).any() or (family_conflicts > 1).any():
        raise ValueError("duplicate flow has conflicting labels")
    return frame.drop_duplicates("flow_id").sort_values("timestamp").reset_index(drop=True)


def matrix(frame: pd.DataFrame) -> np.ndarray:
    return np.log1p(frame[FEATURES].to_numpy(dtype=np.float32))
