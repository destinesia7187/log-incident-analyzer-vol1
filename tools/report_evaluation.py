"""Aggregate separately scoped scenario metrics and publish their denominators."""

import argparse
import json
from pathlib import Path

from lia.common import write_json
from lia.evaluation import wilson


def summarize(rows):
    totals = {
        key: sum(r["metrics"][key] for r in rows)
        for key in [
            "tp",
            "fp",
            "fn",
            "tn",
            "attack_episodes",
            "benign_episodes",
            "unassessed",
            "ambiguous",
            "duplicate_alerts",
            "auxiliary_alerts",
        ]
    }
    tp, fp, fn = totals["tp"], totals["fp"], totals["fn"]
    totals.update(
        precision=tp / (tp + fp) if tp + fp else None,
        eligible_recall=tp / (tp + fn) if tp + fn else None,
        end_to_end_recall=tp / totals["attack_episodes"] if totals["attack_episodes"] else None,
        f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None,
        precision_95ci=wilson(tp, tp + fp),
        recall_95ci=wilson(tp, tp + fn),
        fp_per_100_benign_episodes=100 * fp / totals["benign_episodes"]
        if totals["benign_episodes"]
        else None,
    )
    return totals


def report(directory: Path, suite: Path):
    replay = json.loads((directory / "metrics.json").read_text())
    manifest = json.loads(suite.read_text())
    rows = replay["scenarios"]
    labels = {s["id"]: s["episodes"][0]["label"] for s in manifest["scenarios"]}
    totals = summarize(rows)
    family = {f"DET-{i:03}": summarize([r for r in rows if f"det{i:03}" in r["id"]]) for i in range(1, 9)}
    events = alerts = cases = benign_events = benign_alerts = 0
    for row in rows:
        analysis = json.loads((directory / row["id"] / "analysis.json").read_text())
        events += analysis["event_count"]
        alerts += len(analysis["alerts"])
        cases += len(analysis["cases"])
        if labels[row["id"]] == "benign":
            benign_events += analysis["event_count"]
            benign_alerts += len(analysis["alerts"])
    result = {
        "suite_hash": replay["suite_hash"],
        "contract_scenarios_passed": sum(r["passed"] for r in rows),
        "scenario_count": len(rows),
        "primary_metrics": totals,
        "families": family,
        "all_detector_counts": {
            "events": events,
            "alerts": alerts,
            "cases": cases,
            "case_reduction": 1 - cases / alerts if alerts else None,
            "benign_events": benign_events,
            "alerts_on_benign_events": benign_alerts,
            "alerts_per_10000_benign_events": 10000 * benign_alerts / benign_events,
        },
        "declared_target_passed": totals["precision"] >= 0.85
        and totals["eligible_recall"] >= 0.9
        and all(f["eligible_recall"] >= 0.8 for f in family.values()),
        "limitation": "Authored controlled data. Five attacks per family give wide intervals; no field-accuracy claim. All-detector alert counts include auxiliary alerts and are not primary precision.",
    }
    write_json(directory / "summary.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--suite", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(report(args.run, args.suite), indent=2))
