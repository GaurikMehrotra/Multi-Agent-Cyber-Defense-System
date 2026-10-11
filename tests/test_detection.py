"""Leakage and metric correctness, plus actual CPU model fitting."""

import numpy as np
import pytest

from src.detect.autoencoder import Autoencoder
from src.detect.features import FEATURES, canonical, matrix
from src.detect.fusion import beaconing, dns_anomaly, fuse
from src.detect.thresholds import choose
from src.detect.xgb_model import Detector
from src.eval.detection_eval import metrics, replay_latency
from src.eval.splits import attack_disjoint, cross_dataset, temporal
from src.eval.synthetic import flows


def test_dedup_conflict():
    frame = flows(count=80)
    import pandas as pd

    assert len(canonical(pd.concat([frame, frame]))) == len(frame)
    duplicate = frame.iloc[[0]].copy()
    duplicate["label"] = 1
    duplicate["attack"] = "scan_like"
    with pytest.raises(ValueError):
        canonical(pd.concat([frame, duplicate]))


def test_conflicting_attack_family_duplicate_rejected():
    import pandas as pd

    frame = flows(count=80)
    duplicate = frame.iloc[[1]].copy()
    duplicate["attack"] = "other_family"
    with pytest.raises(ValueError):
        canonical(pd.concat([frame, duplicate]))


def test_all_splits_no_leakage():
    frame = flows()
    partitions = [
        temporal(frame),
        attack_disjoint(frame, "beacon_like"),
        cross_dataset(frame, flows(123, "B").assign(src_ip="172.30.0.11")),
    ]
    for split in partitions:
        assert not set(split.train.flow_id) & set(split.test.flow_id)
        assert split.train.timestamp.max() < split.validation.timestamp.min()
    assert "beacon_like" not in set(partitions[1].train.attack)
    assert "beacon_like" not in set(partitions[1].validation.attack)
    assert set(partitions[2].train.dataset).isdisjoint(partitions[2].test.dataset)


def test_deliberate_leakage_rejected():
    split = temporal(flows())
    split.test = split.train.copy()
    with pytest.raises(ValueError):
        split.validate()
    with pytest.raises(ValueError):
        cross_dataset(flows(), flows())


def test_time_ties_not_split():
    frame = flows()
    frame.loc[1, "timestamp"] = frame.loc[0, "timestamp"]
    assert temporal(frame).validate()


def test_no_label_identifier_features():
    assert not {"label", "attack", "timestamp", "flow_id", "src_ip", "dst_ip", "dataset"} & set(
        FEATURES
    )
    assert matrix(canonical(flows())).shape == (240, 6)


def test_metrics_exact():
    result = metrics([0, 0, 1, 1], [0.1, 0.9, 0.8, 0.2], ["benign", "benign", "a", "b"], 2)
    assert result["precision"] == 0.5 and result["recall"] == 0.5
    assert result["fpr"] == 0.5 and result["alerts_per_benign_day"] == 0.5
    assert result["per_attack_recall"] == {"a": 1.0, "b": 0.0}
    assert result["per_attack_precision_against_benign"] == {"a": 0.5, "b": 0.0}
    assert result["brier"] == pytest.approx(0.375)
    with pytest.raises(ValueError):
        metrics([0], [float("nan")], ["benign"], 1)


def test_threshold_validation_only():
    threshold = choose([0, 0, 1, 1], [0.1, 0.2, 0.8, 0.9], max_fpr=0)
    assert threshold > 0.2 and threshold <= 0.8
    with pytest.raises(ValueError):
        choose([1], [0.8])


def test_cpu_models_and_checkpoint(tmp_path):
    split = temporal(flows(count=80))
    model = Detector(42, 5, 1).fit(split.train)
    assert len(model.predict(split.test)) == len(split.test)
    assert model.explain(split.test.head(2)).shape == (2, 6)
    ae = Autoencoder(42, 4, 2, 1).fit(split.train, split.validation)
    benign = split.train[split.train.label == 0]
    assert np.allclose(ae.scaler.mean_, matrix(benign).mean(axis=0), atol=1e-6)
    path = tmp_path / "ae.pt"
    ae.save(path)
    restored = Autoencoder(42, 4, 2, 1).restore(path)
    assert np.allclose(ae.predict(split.test), restored.predict(split.test))


def test_context_and_replay():
    assert beaconing([0, 10, 20, 30]) == 1
    assert dns_anomaly(["x" * 100]) == 1
    assert np.all(fuse([1], [1], [1], [1]) <= 1)
    assert replay_latency([1], [2], [4])["time_to_decision_mean_seconds"] == 3


def test_scored_evidence_queues_once(factory):
    from sqlalchemy import select

    from src.db.models import Case
    from src.detect.store_scores import enqueue

    scores = [
        {
            "evidence_id": "local-flow",
            "timestamp": "2025-01-01T00:00:00+00:00",
            "src_ip": "172.30.0.10",
            "dst_ip": "172.30.0.11",
            "score": 0.9,
            "alert": True,
        }
    ]
    manifest = {"model": "test-only", "threshold_source": "validation"}
    assert enqueue(factory, scores, manifest)["queued_cases"] == 1
    assert enqueue(factory, scores, manifest)["queued_cases"] == 0
    with factory() as session:
        assert len(list(session.scalars(select(Case)))) == 1


def test_fusion_context_uses_no_future_records():
    from src.detect.fusion import context

    frame = canonical(flows(count=80))
    assert np.allclose(context(frame.head(40)), context(frame)[:40])
    with pytest.raises(ValueError):
        context(frame.iloc[::-1])
