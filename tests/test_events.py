"""Normalization, truncation, deduplication and bounded SQL lookup."""

import pytest

from src.events.correlate import related
from src.events.normalize import eve, zeek
from src.events.schema import Event
from src.events.store import ingest, query
from src.sensors.parse_zeek import ParseStats, records


@pytest.mark.parametrize("kind", ["conn", "dns", "http", "ssl"])
def test_zeek_kinds(kind):
    event = zeek(
        {
            "ts": 1735689600,
            "id.orig_h": "172.30.0.10",
            "id.resp_h": "172.30.0.11",
            "uid": "C1",
            "query": "example.com",
        },
        kind,
    )
    assert event.kind == kind and len(event.evidence_id) == 64


def test_truncated(tmp_path):
    path = tmp_path / "conn.log"
    path.write_text(
        '#separator \x09\n#fields\tts\tid.orig_h\tid.resp_h\n1735689600\t172.30.0.10\t172.30.0.11\ntruncated\n{"bad":\n'
    )
    stats = ParseStats()
    rows = list(records(path, stats))
    assert len(rows) == 1 and stats.rejected == 2
    assert zeek(rows[0]).source == "zeek"


def test_eve():
    event = eve(
        {
            "timestamp": "2025-01-01T00:00:00+00:00",
            "event_type": "alert",
            "src_ip": "172.30.0.10",
            "dest_ip": "172.30.0.11",
            "alert": {"signature": "demo"},
        }
    )
    assert event.fields["alert"]["signature"] == "demo"


def test_dedup_query(factory, obs):
    event = Event.model_validate(obs[0])
    with factory() as session:
        assert ingest(session, event)
        assert not ingest(session, event.model_copy(update={"evidence_id": "forged"}))
        assert len(query(session, "172.30.0.10")) == 1
        assert query(session, "' OR 1=1 --") == []
        with pytest.raises(ValueError):
            query(session, "172.30.0.10", 101)


def test_correlation(obs):
    event = Event.model_validate(obs[0])
    assert related(event, [event]) == [event]


def test_sensor_reprocessing_uid_does_not_break_dedup(factory, obs):
    event = Event.model_validate(obs[0]).model_copy(update={"uid": "first-run"})
    replay = event.model_copy(update={"uid": "second-run"})
    assert event.identified().evidence_id == replay.identified().evidence_id
    with factory() as session:
        assert ingest(session, event)
        assert not ingest(session, replay)


def test_parameterized_time_bounded_log_query(factory, obs):
    from datetime import timedelta

    event = Event.model_validate(obs[0])
    with factory() as session:
        ingest(session, event)
        assert (
            len(
                query(
                    session,
                    str(event.src_ip),
                    start=event.timestamp - timedelta(seconds=1),
                    end=event.timestamp + timedelta(seconds=1),
                )
            )
            == 1
        )
        assert (
            query(
                session,
                str(event.src_ip),
                start=event.timestamp + timedelta(seconds=1),
                end=event.timestamp + timedelta(seconds=2),
            )
            == []
        )
        with pytest.raises(ValueError):
            query(
                session,
                str(event.src_ip),
                start=event.timestamp,
                end=event.timestamp + timedelta(hours=2),
            )


def test_lab_checksum_repair_is_scoped_and_preserves_payload(tmp_path):
    import struct

    from scripts.benign_pcap import generate
    from src.sensors.lab_checksums import checksum, repair, repair_packet

    source = generate(tmp_path / "original.pcap")
    original = source.read_bytes()
    manifest = repair(str(source), str(tmp_path / "derived.pcap"))
    fixed = (tmp_path / "derived.pcap").read_bytes()
    assert source.read_bytes() == original and manifest["payload_modified"] is False
    assert fixed[40 + 14 + 20 + 8 :] == original[40 + 14 + 20 + 8 :]
    frame = fixed[40:]
    assert checksum(frame[14:34]) == 0
    pseudo = frame[26:34] + struct.pack("!BBH", 0, 17, len(frame) - 34)
    assert checksum(pseudo + frame[34:]) == 0
    unsafe = bytearray(frame)
    unsafe[30:34] = bytes([8, 8, 8, 8])
    with pytest.raises(ValueError):
        repair_packet(unsafe)
    with pytest.raises(ValueError):
        repair(str(source), str(source))


def test_invalid_zeek_separator_is_counted_without_crashing(tmp_path):
    path = tmp_path / "bad-header.log"
    path.write_text('#separator \\xZZ\n{"valid":1}\n')
    stats = ParseStats()
    assert list(records(path, stats)) == [{"valid": 1}]
    assert stats.rejected == 1
