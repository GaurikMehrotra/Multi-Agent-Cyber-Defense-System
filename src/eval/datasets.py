"""Local canonical CSV ingestion with explicit terms confirmation and provenance."""

import argparse
import hashlib
import json
from datetime import UTC, date, datetime
from pathlib import Path

import pandas as pd
from pydantic import BaseModel, ConfigDict, Field, HttpUrl, field_validator

from src.detect.features import canonical


class SourceManifest(BaseModel):
    """Require explicit, dated approval without inferring it from public availability."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)
    dataset: str = Field(min_length=1)
    license_url: HttpUrl
    terms_reviewed_on: date
    citation: str = Field(min_length=1)
    known_issues_reviewed: bool = Field(strict=True)
    approved: bool = Field(strict=True)

    @field_validator("approved", "known_issues_reviewed")
    @classmethod
    def require_confirmation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("explicit license/terms/issues review required")
        return value

    @field_validator("terms_reviewed_on")
    @classmethod
    def require_past_review(cls, value: date) -> date:
        if value > datetime.now(UTC).date():
            raise ValueError("review date cannot be in the future")
        return value

    @field_validator("license_url")
    @classmethod
    def reject_embedded_credentials(cls, value: HttpUrl) -> HttpUrl:
        if value.username or value.password:
            raise ValueError("license URL cannot contain credentials")
        return value


def ingest(path, manifest):
    if Path(path).stat().st_size > 64 * 1024 * 1024:
        raise ValueError("use a reviewed CSV sample smaller than 64 MiB on this CPU workflow")
    metadata = SourceManifest.model_validate_json(Path(manifest).read_text()).model_dump(
        mode="json"
    )
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
