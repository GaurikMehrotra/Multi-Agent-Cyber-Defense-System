"""Entity/time correlation is contextual, never proof of causation."""

from src.events.schema import Event


def related(anchor: Event, events: list[Event], window_seconds: int = 60) -> list[Event]:
    entities = {str(anchor.src_ip), str(anchor.dst_ip)}
    return [
        event
        for event in events
        if abs((event.timestamp - anchor.timestamp).total_seconds()) <= window_seconds
        and entities.intersection({str(event.src_ip), str(event.dst_ip)})
    ]
