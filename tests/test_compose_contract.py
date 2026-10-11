"""CI checks static topology only; it never starts containers or scans."""

from pathlib import Path

import yaml


def test_isolated_scanner_and_resource_contract():
    config = yaml.safe_load(Path("docker-compose.yml").read_text())
    assert config["networks"]["lab"]["internal"] is True
    assert config["networks"]["lab"]["ipam"]["config"] == [{"subnet": "172.30.0.0/24"}]
    scanner = config["services"]["nmap"]
    assert set(scanner["networks"]) == {"lab"}
    assert "ports" not in scanner and "network_mode" not in scanner
    assert not any("docker.sock" in mount for mount in scanner["volumes"])
    assert scanner["cap_drop"] == ["ALL"]
    for name in ["zeek", "suricata"]:
        sensor = config["services"][name]
        assert sensor["network_mode"] == "none"
        assert sensor["mem_limit"] == "384m"
        assert any(":/input:ro" in mount for mount in sensor["volumes"])
