"""Score canonical flows using trained CPU models, preserving evidence IDs and timestamps."""

import argparse
import json
from pathlib import Path

from src.baselines.suricata_only import predict as suricata
from src.detect.autoencoder import Autoencoder
from src.detect.features import canonical
from src.detect.fusion import context, fuse
from src.detect.xgb_model import Detector
from src.eval.datasets import ingest


def replay(frame, detector, ae, threshold=0.5):
    frame = canonical(frame)
    scores = fuse(detector.predict(frame), ae.predict(frame), suricata(frame), context(frame))
    return [
        {
            "evidence_id": row.flow_id,
            "timestamp": row.timestamp.isoformat(),
            "score": float(score),
            "alert": bool(score >= threshold),
            "src_ip": row.src_ip,
            "dst_ip": row.dst_ip,
            "score_is_probability": False,
        }
        for (_, row), score in zip(frame.iterrows(), scores, strict=True)
    ]


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv")
    parser.add_argument("manifest")
    parser.add_argument("--model-dir", default="artifacts/detection")
    parser.add_argument("--output", default="artifacts/replay.json")
    parser.add_argument("--threshold", type=float, default=0.5)
    args = parser.parse_args()
    frame, _ = ingest(args.csv, args.manifest)
    directory = Path(args.model_dir)
    cfg = json.loads((directory / "config.json").read_text())
    xgb = Detector()
    xgb.model.load_model(directory / "xgb-temporal-42.json")
    ae = Autoencoder(hidden=int(cfg["models"]["ae_hidden"])).restore(
        directory / "ae-temporal-42.pt"
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(replay(frame, xgb, ae, args.threshold), indent=2))
