"""Evaluation is separate from detection; labels are never passed to the engine."""

from __future__ import annotations

import math
from pathlib import Path

from .common import LiaError, digest, sha_file, write_json
from .config import load_yaml
from .pipeline import analyze


def wilson(success: int, total: int) -> list[float] | None:
    if not total:
        return None
    p, z = success / total, 1.959963984540054
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    delta = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0, center - delta), min(1, center + delta)]


def metrics(alerts: list[dict], episodes: list[dict]) -> dict:
    eligible = [e for e in episodes if e.get("eligible", True) and e["label"] != "ambiguous"]
    attacks = [e for e in eligible if e["label"] == "attack"]
    benign = [e for e in eligible if e["label"] == "benign"]
    candidates = []
    for ai, alert in enumerate(alerts):
        for ei, episode in enumerate(eligible):
            if (
                alert["tenant_id"] != episode["tenant_id"]
                or alert["application_id"] != episode["application_id"]
            ):
                continue
            if (
                alert["rule_id"] not in episode["primary_rules"]
                or alert.get(episode["entity_field"]) != episode["entity_value"]
            ):
                continue
            shared = set(alert["evidence_ids"]) & set(episode["relevant_event_ids"])
            if shared and alert["end"] >= episode["start"] and alert["start"] <= episode["end"]:
                candidates.append(
                    (-len(shared), abs(alert["start"] - episode["start"]), alert["id"], episode["id"], ai, ei)
                )
    used_alerts, used_episodes = set(), set()
    tp = benign_alerts = 0
    for _, _, _, _, ai, ei in sorted(candidates):
        if ai in used_alerts or ei in used_episodes:
            continue
        used_alerts.add(ai)
        used_episodes.add(ei)
        if eligible[ei]["label"] == "attack":
            tp += 1
        else:
            benign_alerts += 1
    # Only primary-rule alerts enter primary precision; auxiliary detectors are reported separately.
    primary_ids = {rid for e in eligible for rid in e["primary_rules"]}
    primary_count = sum(a["rule_id"] in primary_ids for a in alerts)
    fp = primary_count - tp
    fn = len(attacks) - tp
    all_attacks = sum(e["label"] == "attack" for e in episodes)
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / len(attacks) if attacks else None
    duplicate_alerts = len(
        {
            ai
            for ai, ei in {(row[4], row[5]) for row in candidates}
            if ai not in used_alerts and eligible[ei]["label"] == "attack"
        }
    )
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": len(benign) - benign_alerts,
        "precision": precision,
        "eligible_recall": recall,
        "end_to_end_recall": tp / all_attacks if all_attacks else None,
        "f1": (2 * tp / (2 * tp + fp + fn)) if 2 * tp + fp + fn else None,
        "precision_95ci": wilson(tp, tp + fp),
        "recall_95ci": wilson(tp, len(attacks)),
        "duplicate_alerts": duplicate_alerts,
        "benign_episodes": len(benign),
        "attack_episodes": all_attacks,
        "unassessed": sum(not e.get("eligible", True) for e in episodes),
        "ambiguous": sum(e["label"] == "ambiguous" for e in episodes),
        "auxiliary_alerts": len(alerts) - primary_count,
        "fp_per_100_benign_episodes": 100 * benign_alerts / len(benign) if benign else None,
    }


def replay(suite_path: Path, output: Path) -> dict:
    freeze = suite_path.parent / "freeze.json"
    if freeze.exists():
        lock = load_yaml(freeze)
        if lock.get("suite_sha256") != sha_file(suite_path):
            raise LiaError("frozen_suite_changed")
    suite = load_yaml(suite_path)
    if suite.get("schema") != "lia-suite/v1" or not isinstance(suite.get("scenarios"), list):
        raise LiaError("invalid_suite")
    if output.exists():
        raise LiaError("existing_output")
    output.mkdir(parents=True)
    results = []
    for item in suite["scenarios"]:
        sid = item["id"]
        if not isinstance(sid, str) or not sid.replace("-", "").replace("_", "").isalnum():
            raise LiaError("invalid_scenario_id")
        manifest = (suite_path.parent / item["manifest"]).resolve()
        if not manifest.is_relative_to(suite_path.parent.resolve()):
            raise LiaError("unsafe_scenario_path")
        analysis, run, _ = analyze(manifest, output / sid)
        if item.get("dataset_hash") and item["dataset_hash"] != analysis["dataset_hash"]:
            raise LiaError("frozen_dataset_changed")
        observed = {a["rule_id"] for a in analysis["alerts"]}
        expected = set(item.get("expected_rules", []))
        forbidden = set(item.get("forbidden_rules", []))
        result = {
            "id": sid,
            "passed": expected <= observed and not observed & forbidden,
            "observed_rules": sorted(observed),
            "dataset_hash": analysis["dataset_hash"],
            "analysis_hash": run["analysis_hash"],
        }
        if "episodes" in item:
            result["metrics"] = metrics(analysis["alerts"], item["episodes"])
        results.append(result)
    report = {
        "schema_version": "1.0",
        "suite_hash": digest(suite),
        "scenarios": results,
        "passed": all(r["passed"] for r in results),
    }
    write_json(output / "metrics.json", report)
    return report
