"""Independent behavior templates for frozen evaluation v2.

No call into detection and no reuse of development make_events(). Four benign
episodes deliberately meet a detector's conditions: instrumentation cannot reveal intent.
"""

from __future__ import annotations

import json
from pathlib import Path

from lia.common import digest, sha_file, write_json
from lia.config import Manifest, manifest_hash, parse_model
from lia.demo import raw_event, write_input
from lia.normalize import parse_time

ROOT = Path(__file__).resolve().parents[1]


def behavior(det: int, variant: int, attack: bool) -> tuple[list[dict], bool]:
    owner = f"heldout-{det}-{variant}"
    # High-volume benign workflows are retained as expected false positives.
    overlap = not attack and variant == 0 and det in {1, 3, 5, 7}
    meets = attack or overlap
    events = []

    def add(seconds, **values):
        events.append(raw_event(len(events), seconds, user=values.pop("user", owner), **values))

    if det in {1, 3, 6}:
        n = 10 + variant % 5 if meets or det in {3, 6} else 9
        for i in range(n):
            # Irregular intervals, interleaved unrelated successful logins.
            add(20 + i * 13 + i % 3)
            add(21 + i * 13 + i % 3, user=f"noise-{i}", outcome="success")
        if det in {3, 6}:
            add(
                250,
                outcome="success",
                address="192.0.2.10" if meets or det == 6 else "192.0.2.11",
                auth={"session_ref": "heldout-session-a"},
            )
        if det == 6:
            add(
                390,
                action="auth.mfa.enroll",
                outcome="success",
                target={"user_id": owner},
                auth={
                    "session_ref": "heldout-session-a" if meets else "heldout-session-b",
                    "device_ref": "heldout-device",
                },
            )
    elif det == 2:
        identities = 10 + variant % 5 if meets else 9
        for i in range(24):
            add(i * 19, user=f"{owner}-{i % identities}")
    elif det == 4:
        addresses = 5 + variant % 3 if meets else 4
        for i in range(25):
            add(i * 17, address=f"198.51.100.{i % addresses + 1}")
    elif det == 5:
        distinct = 5 + variant % 3 if meets else 4
        for i in range(16):
            add(
                i * 11,
                action="auth.mfa.challenge",
                outcome="requested",
                auth={"mfa_request_id": f"m-{i % distinct}"},
            )
    elif det == 7:
        paths = ["/config", "/backup.zip", "/admin", "/.git/config", "/.env"]
        for i in range(20):
            add(
                i * 23,
                action="http.request",
                outcome="unknown",
                http={"method": "GET", "path": paths[i % (5 if meets else 4)], "status": 404},
            )
    else:
        for i in range(15):
            add(
                i * 13,
                action="authz.check",
                outcome="denied",
                target={"resource_id": f"r-{i % (3 if meets else 2)}"},
            )
    # Arrival order differs from event-time order in every evaluation scenario.
    return events[::2] + list(reversed(events[1::2])), meets


def build(destination: Path):
    if destination.exists():
        raise ValueError("Frozen evaluation must be written to a new version directory")
    scenarios = []
    for det in range(1, 9):
        for label, count in [("attack", 5), ("benign", 10)]:
            for variant in range(count):
                events, matches = behavior(det, variant, label == "attack")
                sid = f"v2-det{det:03}-{label}-{variant:02}"
                path = write_input(destination / sid, events)
                manifest = parse_model(Manifest, json.loads(path.read_text()))
                artifact = {
                    "sha256": sha_file(path.parent / "app.jsonl"),
                    "source_id": "demo-audit",
                    "size": (path.parent / "app.jsonl").stat().st_size,
                }
                start, end = (
                    min(parse_time(e["timestamp"])[0] for e in events),
                    max(parse_time(e["timestamp"])[0] for e in events),
                )
                rid = f"DET-{det:03}"
                scenarios.append(
                    {
                        "id": sid,
                        "version": 2,
                        "split": "evaluation",
                        "family_id": f"{rid}-interleaved-cardinality-session-controls-v2",
                        "description": "Benign behavior overlaps detector conditions"
                        if label == "benign" and matches
                        else "Authored behavioral contract with arrival-order permutation",
                        "origin": "synthetic; independent behavior templates in build_evaluation_v2.py",
                        "generator_version": 2,
                        "seed": None,
                        "manifest": f"{sid}/manifest.yml",
                        "dataset_hash": digest(
                            {"artifacts": [artifact], "manifest": manifest_hash(manifest)}
                        ),
                        "input_hashes": [artifact["sha256"]],
                        "capabilities": manifest.sources[0].declared_capabilities,
                        "context": [],
                        "context_hash": digest([]),
                        "observation_interval": [start, end],
                        "expected_rules": [rid] if matches else [],
                        "forbidden_rules": [] if matches else [rid],
                        "expected_quality_findings": [],
                        "prohibited_conclusions": [
                            "confirmed compromise",
                            "vulnerability proven",
                            "complete ATT&CK coverage",
                        ],
                        "episodes": [
                            {
                                "id": sid,
                                "label": label,
                                "eligible": True,
                                "tenant_id": "local",
                                "application_id": "demo",
                                "entity_field": "client_ip" if det in {2, 7} else "user_id",
                                "entity_value": "192.0.2.10" if det in {2, 7} else f"heldout-{det}-{variant}",
                                "start": start,
                                "end": end,
                                "primary_rules": [rid],
                                "relevant_event_ids": [
                                    digest(["local", "demo", "demo-audit", e["event_id"]])
                                    for e in events
                                    if not e["actor"]["user_id"].startswith("noise-")
                                ],
                            }
                        ],
                    }
                )
    write_json(destination / "manifest.yml", {"schema": "lia-suite/v1", "version": 2, "scenarios": scenarios})
    write_json(
        destination / "freeze.json",
        {
            "version": 2,
            "suite_sha256": sha_file(destination / "manifest.yml"),
            "scenarios": 120,
            "targets_declared_before_replay": {
                "precision": 0.85,
                "eligible_recall": 0.9,
                "family_recall": 0.8,
            },
        },
    )


if __name__ == "__main__":
    build(ROOT / "datasets" / "evaluation-v2")
