"""Fixed connect scans. The tool never accepts flags, DNS or scripts."""

import json
import subprocess  # nosec B404
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, field_validator

from src.tools.scope_guard import target

PROFILE = {"ports": [8000, 8001], "timeout_seconds": 20, "max_rate": 5, "max_retries": 0}


class ScanArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    target: str
    profile: str = "connect"

    @field_validator("target")
    @classmethod
    def guarded(cls, value):
        return target(value)

    @field_validator("profile")
    @classmethod
    def known(cls, value):
        if value != "connect":
            raise ValueError("unknown profile")
        return value


def validate_profiles(path="configs/scan_profiles.yaml"):
    if yaml.safe_load(Path(path).read_text()) != {"connect": PROFILE}:
        raise ValueError("profile does not match immutable allowed configuration")


def command(args: ScanArgs) -> list[str]:
    return [
        "nmap",
        "-sT",
        "-n",
        "-Pn",
        "-p",
        "8000,8001",
        "--max-rate",
        "5",
        "--max-retries",
        "0",
        "--host-timeout",
        "20s",
        "-oX",
        "-",
        target(args.target),
    ]


def scan(args: ScanArgs, budget, audit, run_id: str, runner=subprocess.run):
    validate_profiles()
    budget.consume("scans")
    audit.write(run_id, "scan_attempt", args.model_dump())
    # Executable is only available inside the isolated verification container.
    result = runner(
        command(args), capture_output=True, text=True, timeout=min(22, budget.remaining), check=True
    )
    budget.check()
    if len(result.stdout.encode()) > 65536:
        raise ValueError("scan output too large")
    audit.write(run_id, "scan_result", {"target": args.target, "xml": result.stdout})
    return {"target": args.target, "xml": result.stdout}


if __name__ == "__main__":
    import sys

    from src.agents.budgets import Budget
    from src.db.audit import Audit

    args = ScanArgs.model_validate_json(sys.stdin.readline())
    print(json.dumps(scan(args, Budget(), Audit(), "lab-verification")))
