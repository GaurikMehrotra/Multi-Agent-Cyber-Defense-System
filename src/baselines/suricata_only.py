"""Suricata alert confidence baseline; synthetic scores are not real rule performance."""

import numpy as np


def predict(frame):
    return np.asarray(frame.get("suricata_score", np.zeros(len(frame))), dtype=float)
