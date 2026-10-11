"""Transparent volume/port baseline with the same threshold-selection budget."""

import numpy as np


def predict(frame):
    volume = np.log1p(frame.orig_bytes.to_numpy()) / np.log1p(1_000_000)
    unusual = (~frame.dest_port.isin([53, 80, 443, 8000, 8001])).to_numpy() * 0.3
    return np.clip(volume * 0.7 + unusual, 0, 1)
