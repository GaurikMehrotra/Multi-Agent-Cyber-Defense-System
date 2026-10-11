"""Measure an explicit command's elapsed time and child peak RSS on the machine running it."""

import argparse
import json
import resource
import subprocess  # nosec B404
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--output", default="artifacts/resources.json")
parser.add_argument("command", nargs=argparse.REMAINDER)
args = parser.parse_args()
if not args.command:
    parser.error("supply command after --")
command = args.command[1:] if args.command[0] == "--" else args.command
started = time.perf_counter()
result = subprocess.run(command, check=False)  # nosec B603
record = {
    "command": command,
    "seconds": time.perf_counter() - started,
    "child_peak_ram_mib": resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss / 1024,
    "exit_code": result.returncode,
    "scope": "this machine only; not aggregate Docker memory",
}
path = Path(args.output)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(record, indent=2))
print(json.dumps(record))
raise SystemExit(result.returncode)
