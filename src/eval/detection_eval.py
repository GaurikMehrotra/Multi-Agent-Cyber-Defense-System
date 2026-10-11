"""Fixed-threshold metrics; exposure duration is supplied, never inferred from row count."""

import numpy as np
from sklearn.metrics import average_precision_score, brier_score_loss, precision_score, recall_score

DEFAULT_BINS = 10


def metrics(labels, scores, families, benign_days: float, threshold: float = 0.5) -> dict:
    labels, scores, families = np.asarray(labels), np.asarray(scores), np.asarray(families)
    if (
        benign_days <= 0
        or len(labels) == 0
        or len(scores) != len(labels)
        or len(families) != len(labels)
    ):
        raise ValueError("aligned rows and positive benign exposure required")
    if (
        not np.isfinite(scores).all()
        or ((scores < 0) | (scores > 1)).any()
        or not np.isin(labels, [0, 1]).all()
    ):
        raise ValueError("binary labels and bounded scores required")
    predicted = scores >= threshold
    benign = labels == 0
    false = int(np.sum(predicted & benign))
    ece = 0.0
    for low in np.linspace(0, 1, DEFAULT_BINS, endpoint=False):
        mask = (scores >= low) & (scores < low + 1 / DEFAULT_BINS if low < 0.9 else scores <= 1)
        if mask.any():
            ece += float(mask.mean() * abs(scores[mask].mean() - labels[mask].mean()))
    return {
        "threshold": threshold,
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "fpr": float(false / benign.sum()) if benign.any() else None,
        "alerts_per_benign_day": false / benign_days,
        "brier": float(brier_score_loss(labels, scores)),
        "ece": ece,
        "average_precision": float(average_precision_score(labels, scores))
        if labels.any()
        else None,
        "per_attack_precision_against_benign": {
            str(family): float(
                np.sum(predicted & (families == family) & (labels == 1))
                / max(1, np.sum(predicted & (families == family) & (labels == 1)) + false)
            )
            for family in sorted(set(families[labels == 1]))
        },
        "per_attack_recall": {
            str(family): float(predicted[(families == family) & (labels == 1)].mean())
            for family in sorted(set(families[labels == 1]))
        },
    }


def replay_latency(event_times, detection_times, decision_times):
    detection = np.asarray(detection_times) - np.asarray(event_times)
    decision = np.asarray(decision_times) - np.asarray(event_times)
    if (detection < 0).any() or (decision < detection).any():
        raise ValueError("invalid replay chronology")
    return {
        "time_to_detect_mean_seconds": float(detection.mean()),
        "time_to_decision_mean_seconds": float(decision.mean()),
    }
