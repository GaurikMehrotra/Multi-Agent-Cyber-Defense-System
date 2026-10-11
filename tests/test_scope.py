"""Exhaustive canonicalization and profile escape attempts."""

import subprocess

import pytest
from pydantic import ValidationError

from src.agents.budgets import Budget
from src.agents.killswitch import KillSwitch
from src.db.audit import Audit
from src.security.redteam_suite import TARGETS
from src.tools.nmap_profiles import ScanArgs, command, scan, validate_profiles
from src.tools.scope_guard import target


@pytest.mark.parametrize("value", TARGETS)
def test_reject_targets(value):
    with pytest.raises(ValueError):
        target(value)


@pytest.mark.parametrize("value", ["172.30.0.10", "172.30.0.11"])
def test_authorized(value):
    assert target(value) == value


@pytest.mark.parametrize("last", [0, 1, 2, 9, 12, 20, 254, 255])
def test_no_unknown_lab_hosts(last):
    with pytest.raises(ValueError):
        target(f"172.30.0.{last}")


@pytest.mark.parametrize(
    "flag", ["exploit", "brute", "dos", "intrusive", "-A", "--script safe", "-p-", "-sS"]
)
def test_no_flags(flag):
    with pytest.raises(ValidationError):
        ScanArgs.model_validate({"target": "172.30.0.10", "flags": flag})


@pytest.mark.parametrize("profile", ["exploit", "brute", "dos", "intrusive", "connect;id"])
def test_bad_profiles(profile):
    with pytest.raises(ValidationError):
        ScanArgs(target="172.30.0.10", profile=profile)


def test_pinned_command():
    result = command(ScanArgs(target="172.30.0.10"))
    assert "--script" not in result and "-n" in result and "-sT" in result
    assert result[-1] == "172.30.0.10"
    validate_profiles()


def test_modified_profile(tmp_path):
    path = tmp_path / "profiles.yaml"
    path.write_text("connect: {ports: [22]}\n")
    with pytest.raises(ValueError):
        validate_profiles(path)


def test_mock_scan(tmp_path):
    called = []

    def fake(cmd, **kwargs):
        called.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, 0, stdout="<nmaprun/>")

    result = scan(
        ScanArgs(target="172.30.0.10"),
        Budget(kill=KillSwitch(tmp_path / "STOP")),
        Audit(tmp_path / "audit"),
        "test",
        runner=fake,
    )
    assert result["xml"] == "<nmaprun/>"
    assert called[0][1]["timeout"] <= 22


def test_gateway_entrypoint_starts_server(monkeypatch):
    """Regression: constructing an HTTPServer without serving must fail this test."""
    import http.server
    import runpy

    calls = []

    class MockServer:
        def __init__(self, address, handler):
            assert address == ("0.0.0.0", 8090)

        def serve_forever(self):
            calls.append("serving")

    monkeypatch.setenv("VERIFY_API_KEY", "unit-test-only")
    monkeypatch.setattr(http.server, "HTTPServer", MockServer)
    runpy.run_module("src.tools.verification_server", run_name="__main__")
    assert calls == ["serving"]
