"""Transparent fusion and context. Correlation raises hypotheses, not verdicts."""

import numpy as np


def fuse(xgb, anomaly, suricata, context):
    return np.clip(
        0.35 * np.asarray(xgb)
        + 0.25 * np.asarray(anomaly)
        + 0.3 * np.asarray(suricata)
        + 0.1 * np.asarray(context),
        0,
        1,
    )


def beaconing(timestamps):
    intervals = np.diff(sorted(timestamps))
    if len(intervals) < 3 or intervals.mean() <= 0:
        return 0.0
    return float(np.clip(1 - intervals.std() / intervals.mean(), 0, 1))


def dns_anomaly(names):
    return float(np.mean([len(str(name)) > 80 for name in names])) if names else 0.0


def context(frame):
    """Causal port, repeated-timing and DNS-length context, never future records."""
    histories = {}
    scores = []
    if not frame.timestamp.is_monotonic_increasing:
        raise ValueError("context requires chronological records")
    for _, row in frame.iterrows():
        key = (row.src_ip, row.dst_ip, row.dest_port)
        history = histories.setdefault(key, [])
        history.append(row.timestamp.timestamp())
        # Four timestamps are the minimum required for three observed intervals.
        history[:] = history[-4:]
        port = float(row.dest_port not in {53, 80, 443, 8000, 8001})
        timing = beaconing(history)
        query = row.get("dns_query", "")
        dns = dns_anomaly([query])
        scores.append(float(np.mean([port, timing, dns])))
    return np.asarray(scores)
