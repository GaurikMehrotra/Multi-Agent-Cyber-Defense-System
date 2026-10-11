"""Cross-process fail-closed stop flag; no tool can clear it."""

import os
from pathlib import Path


class KillSwitch:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.getenv("STOP_FILE", "runtime/STOP"))

    def check(self):
        if self.path.exists():
            raise RuntimeError("global stop active")

    def stop(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch()
