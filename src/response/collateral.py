"""Dependency effects are evaluated by Simulator.score."""

from src.response.simulator import Simulator


def score(simulator: Simulator):
    return simulator.score()
