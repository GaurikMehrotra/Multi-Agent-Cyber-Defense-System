"""Stable evidence timeline."""


def timeline(events):
    return sorted(
        [
            {
                "timestamp": event.timestamp.isoformat(),
                "evidence_id": event.evidence_id,
                "kind": event.kind,
            }
            for event in events
        ],
        key=lambda row: row["timestamp"],
    )
