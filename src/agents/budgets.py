"""Monotonic wall-clock and atomic consumption of per-run budgets."""

import threading
import time

from src.agents.killswitch import KillSwitch
from src.config import Budgets


class Budget:
    def __init__(self, limits: Budgets | None = None, kill: KillSwitch | None = None):
        self.limits = limits or Budgets()
        self.kill = kill or KillSwitch()
        self.started = time.monotonic()
        self.counts = {"tools": 0, "scans": 0, "llm": 0}
        self.lock = threading.Lock()

    def check(self):
        self.kill.check()
        if time.monotonic() - self.started >= self.limits.seconds:
            raise RuntimeError("wall-clock budget exhausted")

    def consume(self, kind: str):
        with self.lock:
            self.check()
            if kind not in self.counts or self.counts[kind] >= getattr(self.limits, kind):
                raise RuntimeError(f"{kind} budget exhausted")
            self.counts[kind] += 1

    @property
    def remaining(self):
        return max(0, self.limits.seconds - (time.monotonic() - self.started))
