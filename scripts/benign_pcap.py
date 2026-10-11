"""Generate a tiny benign DNS PCAP offline, without network sockets."""

import ipaddress
import struct
from pathlib import Path


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def generate(path="data/pcaps/benign.pcap"):
    dns = (
        struct.pack("!HHHHHH", 1, 256, 1, 0, 0, 0)
        + b"\x07example\x03com\x00"
        + struct.pack("!HH", 1, 1)
    )
    udp = struct.pack("!HHHH", 53000, 53, 8 + len(dns), 0) + dns
    header = struct.pack(
        "!BBHHHBBH4s4s",
        69,
        0,
        20 + len(udp),
        1,
        0,
        64,
        17,
        0,
        ipaddress.ip_address("172.30.0.10").packed,
        ipaddress.ip_address("172.30.0.11").packed,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    frame = bytes.fromhex("0200000000110200000000100800") + header + udp
    packet = struct.pack("<IIII", 1735689600, 0, len(frame), len(frame)) + frame
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + packet)
    return output


if __name__ == "__main__":
    print(generate())
