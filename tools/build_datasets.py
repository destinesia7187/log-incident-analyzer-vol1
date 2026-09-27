"""Author and freeze synthetic suites. No detection code is called to create labels."""

from __future__ import annotations

import json
from pathlib import Path

from lia.common import digest, sha_file, write_json
from lia.config import Manifest, manifest_hash, parse_model
from lia.demo import raw_event, write_input
from lia.normalize import parse_time

ROOT = Path(__file__).resolve().parents[1]


def make_events(det: int, variant: int, kind: str) -> list[dict]:
    # Two bursts and independent benign noise give evaluation a different temporal layout
    # from the short contiguous unit fixtures. The intent labels are authored here.
    count = 12 if kind == "attack" else 3
    user = f"eval-user-{det}-{variant}"

    def event(i, **kw):
        return raw_event(i, i * 7 + (30 if i > 5 else 0) + variant * 3, user=user, **kw)

    if det in (1, 3, 6):
        result = [event(i) for i in range(count)]
        if det in (3, 6):
            result.append(
                raw_event(
                    100, 200 + variant * 3, outcome="success", user=user, auth={"session_ref": "eval-session"}
                )
            )
        if det == 6:
            result.append(
                raw_event(
                    101,
                    240 + variant * 3,
                    action="auth.mfa.enroll",
                    outcome="success",
                    user=user,
                    target={"user_id": user},
                    auth={"session_ref": "eval-session", "device_ref": "eval-device"},
                )
            )
    elif det == 2:
        result = [raw_event(i, i * 11 + variant * 3, user=f"{user}-{i}") for i in range(count)]
    elif det == 4:
        result = [
            raw_event(i, i * 9 + variant * 3, user=user, address=f"198.51.100.{i % 5 + 1}")
            for i in range(24 if kind == "attack" else 9)
        ]
    elif det == 5:
        result = [
            event(
                i, action="auth.mfa.challenge", outcome="requested", auth={"mfa_request_id": f"challenge-{i}"}
            )
            for i in range(6 if kind == "attack" else 2)
        ]
    elif det == 7:
        paths = ["/.env", "/.git/config", "/admin", "/backup.zip", "/config"]
        result = [
            event(
                i, action="http.request", outcome="unknown", http={"method": "GET", "path": p, "status": 404}
            )
            for i, p in enumerate(paths if kind == "attack" else paths[:2])
        ]
    else:
        result = [
            event(i, action="authz.check", outcome="denied", target={"resource_id": f"resource-{i % 4}"})
            for i in range(count)
        ]
    if kind == "degraded":
        for e in result:
            if det == 7:
                e["network"]["peer_ip"] = None
            elif det == 6:
                e.get("auth", {}).pop("session_ref", None)
            else:
                e["actor"]["user_id"] = None
    # Nonmatching events are deliberately interleaved and have a different actor.
    result.extend(
        raw_event(
            1000 + i, i * 13 + 2, user=f"ordinary-{i}", action="auth.password.reset", outcome="requested"
        )
        for i in range(3 + variant)
    )
    return result


def build(root: Path, evaluation: bool) -> dict:
    scenarios = []
    for det in range(1, 9):
        kinds = (
            ["attack"] * 5 + ["benign"] * 10
            if evaluation
            else ["attack"] * 2 + ["benign"] * 2 + ["degraded"] * 2
        )
        for variant, kind in enumerate(kinds):
            sid = f"det{det:03}-{kind}-{variant:02}"
            events = make_events(det, variant, kind)
            manifest = write_input(root / sid, events)
            doc = json.loads(manifest.read_text())
            logical = manifest_hash(parse_model(Manifest, doc))
            artifact = {
                "sha256": sha_file(manifest.parent / "app.jsonl"),
                "source_id": "demo-audit",
                "size": (manifest.parent / "app.jsonl").stat().st_size,
            }
            dataset_hash = digest({"artifacts": [artifact], "manifest": logical})
            rid = f"DET-{det:03}"
            # Relevant IDs are derived only from the documented identity contract.
            event_ids = [
                digest(["local", "demo", "demo-audit", e["event_id"]])
                for e in events
                if e["action"] != "auth.password.reset"
            ]
            entity_field = "client_ip" if det in (2, 7) else "user_id"
            entity = "192.0.2.10" if entity_field == "client_ip" else f"eval-user-{det}-{variant}"
            episode = {
                "id": sid,
                "label": "attack" if kind == "attack" else "ambiguous" if kind == "degraded" else "benign",
                "eligible": kind != "degraded",
                "tenant_id": "local",
                "application_id": "demo",
                "entity_field": entity_field,
                "entity_value": entity,
                "start": min(parse_time(e["timestamp"])[0] for e in events),
                "end": max(parse_time(e["timestamp"])[0] for e in events),
                "primary_rules": [rid],
                "relevant_event_ids": event_ids,
            }
            scenarios.append(
                {
                    "id": sid,
                    "family_id": f"{rid}-two-burst" if evaluation else f"{rid}-contract",
                    "split": "evaluation" if evaluation else "development",
                    "origin": "authored synthetic events",
                    "manifest": f"{sid}/manifest.yml",
                    "dataset_hash": dataset_hash,
                    "expected_rules": [rid] if kind == "attack" else [],
                    "forbidden_rules": [rid] if kind != "attack" else [],
                    "episodes": [episode],
                }
            )
    suite = {
        "schema": "lia-suite/v1",
        "version": 1,
        "generator": "tools/build_datasets.py",
        "scenarios": scenarios,
    }
    write_json(root / "manifest.yml", suite)
    write_json(
        root / "freeze.json",
        {"suite_sha256": sha_file(root / "manifest.yml"), "version": 1, "scenarios": len(scenarios)},
    )
    return suite


if __name__ == "__main__":
    for name, is_eval in [("development", False), ("evaluation", True)]:
        root = ROOT / "datasets" / name
        if (root / "freeze.json").exists():
            raise SystemExit("Dataset already frozen; author a new version explicitly.")
        build(root, is_eval)
    print("Authored 48 development and 120 evaluation scenarios.")
