"""Audit installed packages plus official source versions of CPU-only ML distributions."""

import importlib.metadata
import json
import subprocess  # nosec B404
import sys
from pathlib import Path

output = Path("artifacts/dependency-audit")
output.mkdir(parents=True, exist_ok=True)


def run(arguments: list[str]) -> int:
    return subprocess.run([sys.executable, "-m", "pip_audit", *arguments], check=False).returncode  # nosec B603


installed_file = output / "installed.json"
status = run(["--format", "json", "--output", str(installed_file)])
if status:
    raise SystemExit(status)
report = json.loads(installed_file.read_text())
unexpected_skips = [
    row for row in report["dependencies"] if row.get("skip_reason") and row["name"] != "torch"
]
if unexpected_skips:
    raise SystemExit(
        "Unresolved audit skips: " + ", ".join(row["name"] for row in unexpected_skips)
    )
# PyPI's advisory API does not recognize '+cpu' local version identifiers.
# Conservatively audit the same official source release as well; do not ignore CVEs.
source_requirements = output / "source-versions.txt"
torch_version = importlib.metadata.version("torch").split("+", 1)[0]
xgb_version = importlib.metadata.version("xgboost-cpu")
source_requirements.write_text(f"torch=={torch_version}\nxgboost=={xgb_version}\n")
status = run(
    [
        "--no-deps",
        "--disable-pip",
        "-r",
        str(source_requirements),
        "--format",
        "json",
        "--output",
        str(output / "cpu-source.json"),
    ]
)
if status:
    raise SystemExit(status)
source = json.loads((output / "cpu-source.json").read_text())
if any(row.get("skip_reason") for row in source["dependencies"]):
    raise SystemExit("CPU source advisory audit was incomplete")
print(
    "Installed-package and CPU source-release advisory audits passed; OS/native binary scanning is separate."
)
