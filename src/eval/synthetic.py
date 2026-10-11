"""Generated development rows; never a public-dataset accuracy benchmark."""

import numpy as np
import pandas as pd


def flows(seed=42, dataset="generated-A", count=240):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(count):
        family = ["benign", "scan_like", "beacon_like", "benign"][i % 4]
        attack = int(family != "benign")
        rows.append(
            {
                "timestamp": pd.Timestamp("2025-01-01", tz="UTC") + pd.Timedelta(seconds=i * 360),
                "src_ip": "172.30.0.10",
                "dst_ip": "172.30.0.11",
                "src_port": 20000 + i,
                "dest_port": 8000 if not attack else 12345,
                "protocol": "tcp",
                "duration": float(rng.uniform(0.1, 5)),
                "orig_bytes": int(
                    rng.integers(100, 5000) if not attack else rng.integers(5000, 50000)
                ),
                "resp_bytes": int(rng.integers(100, 5000)),
                "orig_pkts": int(rng.integers(1, 30)),
                "resp_pkts": int(rng.integers(1, 30)),
                "label": attack,
                "attack": family,
                "dataset": dataset,
                "suricata_score": float(
                    rng.uniform(0, 0.3) if not attack else rng.uniform(0.2, 0.9)
                ),
            }
        )
    return pd.DataFrame(rows)
