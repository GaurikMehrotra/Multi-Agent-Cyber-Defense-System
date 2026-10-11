"""Public availability and malformed provenance never imply owner approval."""

import json

import pytest

from src.eval.datasets import ingest
from src.eval.synthetic import flows


def approved_manifest():
    return {
        "dataset": "generated-A",
        "license_url": "https://example.com/test-only-terms",
        "terms_reviewed_on": "2020-01-01",
        "citation": "Algorithmic test fixture; no public source approval",
        "known_issues_reviewed": True,
        "approved": True,
        "variant": "test-only",
    }


@pytest.mark.parametrize(
    "update",
    [
        {"approved": False},
        {"approved": "true"},
        {"known_issues_reviewed": False},
        {"citation": "   "},
        {"terms_reviewed_on": "2999-01-01"},
        {"license_url": "not-a-url"},
        {"license_url": "https://user:secret@example.com/terms"},
    ],
)
def test_reject_invalid_or_unapproved_manifest(tmp_path, update):
    source = tmp_path / "source.csv"
    flows(dataset="generated-A", count=12).to_csv(source, index=False)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({**approved_manifest(), **update}))
    with pytest.raises(ValueError):
        ingest(source, manifest)


def test_approved_test_provenance_preserves_variant_and_hash(tmp_path):
    source = tmp_path / "source.csv"
    flows(dataset="generated-A", count=12).to_csv(source, index=False)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps(approved_manifest()))
    frame, metadata = ingest(source, manifest)
    assert not frame.empty
    assert metadata["variant"] == "test-only"
    assert len(metadata["sha256"]) == 64
    assert metadata["terms_reviewed_on"] == "2020-01-01"
