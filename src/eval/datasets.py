"""Local canonical CSV ingestion with explicit terms confirmation and provenance."""

import argparse
import hashlib
import json
from pathlib import Path

import pandas as pd

from src.detect.features import canonical


def ingest(path, manifest):
    if Path(path).stat().st_size > 64 * 1024 * 1024:
        raise ValueError("use a reviewed CSV sample smaller than 64 MiB on this CPU workflow")
    metadata = json.loads(Path(manifest).read_text())
    required = {
        "dataset",
        "license_url",
        "terms_reviewed_on",
        "citation",
        "known_issues_reviewed",
        "approved",
    }
    if (
        not required.issubset(metadata)
        or metadata["approved"] is not True
        or metadata["known_issues_reviewed"] is not True
    ):
        raise ValueError("explicit license/terms/issues review required")
    frame = canonical(pd.read_csv(path))
    if set(frame.dataset) != {metadata["dataset"]}:
        raise ValueError("dataset manifest mismatch")
    metadata["sha256"] = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return frame, metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv")
    parser.add_argument("manifest")
    parser.add_argument("--output", default="data/flows/canonical.csv")
    args = parser.parse_args()
    frame, metadata = ingest(args.csv, args.manifest)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output, index=False)
    output.with_suffix(".manifest.json").write_text(json.dumps(metadata, indent=2))
