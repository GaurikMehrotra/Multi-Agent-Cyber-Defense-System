"""Offline sensor invocation with no network and a read-only PCAP mount."""

import subprocess  # nosec B404
from pathlib import Path

IMAGE = "zeek/zeek:7.0.4@sha256:a6492105946f483606ee2c907a6881c6d9ae18a1d0e9171cde0b30355d57a9da"


def run(pcap, output):
    pcap, output = Path(pcap).resolve(), Path(output).resolve()
    if not pcap.is_file() or pcap.suffix not in {".pcap", ".pcapng"}:
        raise ValueError("local PCAP required")
    output.mkdir(parents=True, exist_ok=True)
    import os

    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--memory",
        "384m",
        "--cpus",
        "1",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-v",
        f"{pcap}:/input/sample.pcap:ro",
        "-v",
        f"{output}:/output",
        "-w",
        "/output",
        "--entrypoint",
        "zeek",
        IMAGE,
        "-r",
        "/input/sample.pcap",
        "LogAscii::use_json=T",
    ]
    subprocess.run(command, check=True, timeout=120)  # nosec B603
