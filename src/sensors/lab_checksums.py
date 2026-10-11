"""Repair checksum-offloaded IPv4 lab packets in a derived PCAP, preserving original bytes.
Never use this on public/real captures. It repairs checksum fields, not payloads,
and is not evidence that a capture was authentic or complete.
"""

import argparse
import hashlib
import ipaddress
import json
import struct
from pathlib import Path

LAB = ipaddress.IPv4Network("172.30.0.0/24")


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def repair_packet(packet: bytes) -> bytes:
    if len(packet) < 34 or packet[12:14] != b"\x08\x00":
        raise ValueError("only Ethernet IPv4 lab packets supported")
    data = bytearray(packet)
    header = (data[14] & 15) * 4
    total = struct.unpack("!H", data[16:18])[0]
    if data[14] >> 4 != 4 or header < 20 or len(data) < 14 + total:
        raise ValueError("truncated IPv4 frame")
    src, dst = bytes(data[26:30]), bytes(data[30:34])
    if any(ipaddress.IPv4Address(ip) not in LAB for ip in (src, dst)):
        raise ValueError("non-lab traffic forbidden")
    fragment = struct.unpack("!H", data[20:22])[0]
    if fragment & 0x3FFF:
        raise ValueError("fragmented traffic unsupported")
    protocol = data[23]
    if protocol not in {6, 17}:
        raise ValueError("only lab TCP/UDP supported")
    start = 14 + header
    offset = 16 if protocol == 6 else 6
    segment = bytearray(data[start : 14 + total])
    if len(segment) < offset + 2:
        raise ValueError("truncated transport segment")
    segment[offset : offset + 2] = b"\0\0"
    pseudo = src + dst + struct.pack("!BBH", 0, protocol, len(segment))
    value = checksum(pseudo + segment)
    if protocol == 17 and value == 0:
        value = 65535
    segment[offset : offset + 2] = struct.pack("!H", value)
    data[start : 14 + total] = segment
    data[24:26] = b"\0\0"
    data[24:26] = struct.pack("!H", checksum(data[14 : 14 + header]))
    return bytes(data)


def repair(source: str, output: str) -> dict:
    original = Path(source).read_bytes()
    if (
        len(original) < 24
        or original[:4] != b"\xd4\xc3\xb2\xa1"
        or struct.unpack("<I", original[20:24])[0] != 1
    ):
        raise ValueError("classic little-endian Ethernet PCAP required")
    result = bytearray(original[:24])
    position, packets, changed = 24, 0, 0
    while position < len(original):
        if position + 16 > len(original):
            raise ValueError("truncated PCAP record")
        record = original[position : position + 16]
        length = struct.unpack("<IIII", record)[2]
        position += 16
        packet = original[position : position + length]
        if len(packet) != length:
            raise ValueError("truncated packet")
        fixed = repair_packet(packet)
        changed += int(fixed != packet)
        result.extend(record + fixed)
        packets += 1
        position += length
    path = Path(output)
    if path.resolve() == Path(source).resolve():
        raise ValueError("original must remain unchanged")
    if path.exists() and path.read_bytes() != result:
        raise ValueError("refusing to overwrite different existing output")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(result)
    manifest = {
        "original_sha256": hashlib.sha256(original).hexdigest(),
        "derived_sha256": hashlib.sha256(result).hexdigest(),
        "packets": packets,
        "checksum_fields_changed_packets": changed,
        "payload_modified": False,
        "purpose": "isolated lab checksum-offload repair; not for public or real captures",
    }
    path.with_suffix(".provenance.json").write_text(json.dumps(manifest, indent=2))
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source")
    parser.add_argument("output")
    args = parser.parse_args()
    print(json.dumps(repair(args.source, args.output)))
