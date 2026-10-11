"""Offline Suricata with only the project-authored licensed demonstration rule."""

import os
import subprocess  # nosec B404
from pathlib import Path

IMAGE = "jasonish/suricata:7.0.8@sha256:89b300fb5d00f182359a1305543e828a804ede7f1685e75b05f607f7372428c6"


def run(pcap, output, config_dir="configs"):
    pcap, output, config = Path(pcap).resolve(), Path(output).resolve(), Path(config_dir).resolve()
    if not pcap.is_file() or pcap.suffix not in {".pcap", ".pcapng"}:
        raise ValueError("local PCAP required")
    output.mkdir(parents=True, exist_ok=True)
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
        "-v",
        f"{config}:/rules:ro",
        "--entrypoint",
        "suricata",
        IMAGE,
        "--runmode",
        "single",
        "-c",
        "/rules/suricata.yaml",
        "-r",
        "/input/sample.pcap",
        "-l",
        "/output",
    ]
    subprocess.run(command, check=True, timeout=120)  # nosec B603
