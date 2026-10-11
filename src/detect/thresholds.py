"""Validation-only threshold selection with an explicit false-positive budget."""

import numpy as np


def choose(labels, scores, max_fpr: float = 0.05) -> float:
    labels, scores = np.asarray(labels), np.asarray(scores)
    if not (labels == 0).any():
        raise ValueError("validation requires benign samples")
    candidates = sorted(set([0.0, 0.5, 1.0, *scores.tolist()]))
    feasible = []
    for threshold in candidates:
        pred = scores >= threshold
        fpr = pred[labels == 0].mean()
        recall = pred[labels == 1].mean() if (labels == 1).any() else 0
        if fpr <= max_fpr:
            feasible.append((recall, -fpr, threshold))
    return float(max(feasible)[2]) if feasible else float(np.nextafter(1.0, 2.0))
