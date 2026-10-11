"""Explicit chronological, attack-disjoint, and external-dataset partitions."""

from dataclasses import dataclass

import pandas as pd

from src.detect.features import canonical


@dataclass
class Split:
    train: pd.DataFrame
    validation: pd.DataFrame
    test: pd.DataFrame
    name: str

    def validate(self):
        sets = [set(part.flow_id) for part in (self.train, self.validation, self.test)]
        if any(sets[i] & sets[j] for i in range(3) for j in range(i + 1, 3)):
            raise ValueError("flow leakage")
        if any(part.empty for part in (self.train, self.validation, self.test)):
            raise ValueError("empty partition")
        if self.train.timestamp.max() >= self.validation.timestamp.min():
            raise ValueError("training/validation time overlap")
        if (
            self.name != "cross_dataset"
            and self.validation.timestamp.max() >= self.test.timestamp.min()
        ):
            raise ValueError("validation/test time overlap")
        return self


def temporal(frame: pd.DataFrame) -> Split:
    frame = canonical(frame)
    times = sorted(frame.timestamp.unique())
    if len(times) < 10:
        raise ValueError("need at least ten distinct timestamps")
    a, b = times[int(len(times) * 0.6)], times[int(len(times) * 0.8)]
    return Split(
        frame[frame.timestamp < a],
        frame[(frame.timestamp >= a) & (frame.timestamp < b)],
        frame[frame.timestamp >= b],
        "temporal",
    ).validate()


def attack_disjoint(frame: pd.DataFrame, held_out: str) -> Split:
    if held_out == "benign":
        raise ValueError("hold out an attack family")
    result = temporal(frame)
    result.train = result.train[result.train.attack != held_out]
    result.validation = result.validation[result.validation.attack != held_out]
    result.test = result.test[result.test.attack.isin(["benign", held_out])]
    result.name = "attack_disjoint"
    if held_out not in set(result.test.attack):
        raise ValueError("held-out family absent from test period")
    return result.validate()


def cross_dataset(train: pd.DataFrame, external: pd.DataFrame) -> Split:
    source = temporal(train)
    target = canonical(external)
    if set(source.train.dataset) & set(target.dataset):
        raise ValueError("cross-dataset sources must differ")
    return Split(source.train, source.validation, target, "cross_dataset").validate()
