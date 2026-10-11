"""Normalize sensor-specific records without trusting embedded traffic text."""

from datetime import UTC, datetime

from src.events.schema import Event


def zeek(row: dict, kind: str = "conn") -> Event:
    fields = {
        k: v
        for k, v in row.items()
        if k not in {"ts", "uid", "id.orig_h", "id.resp_h", "id.orig_p", "id.resp_p"}
    }
    return Event(
        timestamp=datetime.fromtimestamp(float(row["ts"]), UTC),
        source="zeek",
        kind=kind,
        src_ip=row["id.orig_h"],
        dst_ip=row["id.resp_h"],
        src_port=int(row.get("id.orig_p") or 0),
        dst_port=int(row.get("id.resp_p") or 0),
        uid=row.get("uid"),
        fields=fields,
    ).identified()


def eve(row: dict) -> Event:
    return Event(
        timestamp=row["timestamp"],
        source="suricata",
        kind=row["event_type"],
        src_ip=row["src_ip"],
        dst_ip=row["dest_ip"],
        src_port=row.get("src_port", 0),
        dst_port=row.get("dest_port", 0),
        uid=str(row.get("flow_id", "")),
        fields={k: row[k] for k in ("alert", "dns", "http", "tls", "flow") if k in row},
    ).identified()
