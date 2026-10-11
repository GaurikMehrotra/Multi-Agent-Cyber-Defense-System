"""Run deterministic safety regression without network or scans."""

import json
from pathlib import Path

from src.security.redteam_suite import run


def main(output="artifacts/safety.json"):
    result = run()
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2))
    print(json.dumps({key: result[key] for key in ["attempts", "blocked", "escaped"]}))
    if result["escaped"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
