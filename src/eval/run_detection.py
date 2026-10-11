"""Reproducible detection harness; generated demonstration is the default, not a benchmark."""

import argparse
import json
import resource
import time
from pathlib import Path

import numpy as np

from src.baselines.heuristic import predict as heuristic
from src.baselines.suricata_only import predict as suricata
from src.config import load
from src.detect.autoencoder import Autoencoder
from src.detect.features import canonical
from src.detect.fusion import context, fuse
from src.detect.thresholds import choose
from src.detect.xgb_model import Detector
from src.eval.datasets import ingest
from src.eval.detection_eval import metrics
from src.eval.splits import attack_disjoint, cross_dataset, temporal
from src.eval.synthetic import flows

SEEDS = [11, 23, 42]


def evaluate(
    source, target, output, config, benign_days, held_out="beacon_like", provenance="generated_demo"
):
    path = Path(output)
    path.mkdir(parents=True, exist_ok=True)
    splits = [temporal(source), attack_disjoint(source, held_out), cross_dataset(source, target)]
    rows = []
    for split in splits:
        for seed in SEEDS:
            started = time.perf_counter()
            xgb = Detector(seed, int(config.models["xgb_estimators"]), config.threads).fit(
                split.train
            )
            ae = Autoencoder(
                seed,
                int(config.models["ae_hidden"]),
                int(config.models["ae_epochs"]),
                config.threads,
                config.models["ae_quantile"],
            ).fit(split.train, split.validation)
            validation = {
                "xgboost": xgb.predict(split.validation),
                "autoencoder": ae.predict(split.validation),
                "suricata": suricata(split.validation),
                "heuristic": heuristic(split.validation),
            }
            test = {
                "xgboost": xgb.predict(split.test),
                "autoencoder": ae.predict(split.test),
                "suricata": suricata(split.test),
                "heuristic": heuristic(split.test),
            }
            validation["fusion"] = fuse(
                validation["xgboost"],
                validation["autoencoder"],
                validation["suricata"],
                context(split.validation),
            )
            test["fusion"] = fuse(
                test["xgboost"], test["autoencoder"], test["suricata"], context(split.test)
            )
            for method, scores in test.items():
                threshold = choose(split.validation.label, validation[method])
                rows.append(
                    {
                        "split": split.name,
                        "method": method,
                        "seed": seed,
                        "provenance": provenance,
                        "metrics": metrics(
                            split.test.label, scores, split.test.attack, benign_days, threshold
                        ),
                        "fixed_threshold_metrics": metrics(
                            split.test.label,
                            scores,
                            split.test.attack,
                            benign_days,
                            config.threshold,
                        ),
                        "elapsed_stage_seconds": time.perf_counter() - started,
                        "process_peak_ram_mib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
                        / 1024,
                    }
                )
            np.save(path / f"shap-{split.name}-{seed}.npy", xgb.explain(split.test.head(10)))
            xgb.model.save_model(path / f"xgb-{split.name}-{seed}.json")
            ae.save(path / f"ae-{split.name}-{seed}.pt")
    summary = []
    for split in splits:
        for method in ["xgboost", "autoencoder", "suricata", "heuristic", "fusion"]:
            selected = [
                row for row in rows if row["split"] == split.name and row["method"] == method
            ]
            result = {"split": split.name, "method": method}
            for name in ["precision", "recall", "fpr", "alerts_per_benign_day", "brier", "ece"]:
                values = [
                    row["metrics"][name] for row in selected if row["metrics"][name] is not None
                ]
                result[name] = {
                    "mean": float(np.mean(values)) if values else None,
                    "std": float(np.std(values, ddof=1)) if len(values) > 1 else None,
                }
            for metric_name in ["per_attack_recall", "per_attack_precision_against_benign"]:
                families = sorted(
                    {family for row in selected for family in row["metrics"][metric_name]}
                )
                result[metric_name] = {}
                for family in families:
                    values = [
                        row["metrics"][metric_name][family]
                        for row in selected
                        if family in row["metrics"][metric_name]
                    ]
                    result[metric_name][family] = {
                        "mean": float(np.mean(values)),
                        "std": float(np.std(values, ddof=1)) if len(values) > 1 else None,
                    }
            summary.append(result)
    (path / "results.json").write_text(json.dumps(rows, indent=2))
    (path / "summary.json").write_text(json.dumps(summary, indent=2))
    (path / "config.json").write_text(config.model_dump_json(indent=2))
    (path / "metadata.json").write_text(
        json.dumps(
            {
                "provenance": provenance,
                "seeds": SEEDS,
                "benign_days": benign_days,
                "warning": "Generated data is plumbing validation only. Scores, including anomaly fusion, are not calibrated probabilities.",
            },
            indent=2,
        )
    )
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(10, 4))
    labels = [row["split"] + "/" + row["method"] for row in summary]
    ax.bar(labels, [row["recall"]["mean"] for row in summary])
    ax.set_ylabel("Recall (generated demonstration)")
    ax.tick_params(axis="x", rotation=90)
    fig.tight_layout()
    fig.savefig(path / "recall.png")
    plt.close(fig)
    return rows


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source")
    parser.add_argument("--source-manifest")
    parser.add_argument("--target")
    parser.add_argument("--target-manifest")
    parser.add_argument("--benign-days", type=float, default=None)
    parser.add_argument("--held-out", default="beacon_like")
    parser.add_argument("--output", default="artifacts/detection")
    parser.add_argument("--config", default="configs/fast_debug.yaml")
    args = parser.parse_args()
    if args.source:
        if not all([args.target, args.source_manifest, args.target_manifest, args.benign_days]):
            parser.error(
                "real evaluation requires both manifests, target and measured benign exposure"
            )
        source, _ = ingest(args.source, args.source_manifest)
        target, _ = ingest(args.target, args.target_manifest)
        provenance = "user_approved_public_data"
        days = args.benign_days
    else:
        source = flows()
        target = flows(seed=123, dataset="generated-B").assign(src_ip="172.30.0.11")
        provenance = "generated_demo"
        days = 1.0  # Explicit artificial exposure; not a measured day of traffic.
    rows = evaluate(
        canonical(source),
        canonical(target),
        args.output,
        load(args.config),
        days,
        args.held_out,
        provenance,
    )
    print(f"Completed {len(rows)} method/seed/split evaluations ({provenance})")
