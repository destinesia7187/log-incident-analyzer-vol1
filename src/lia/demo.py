"""Small deterministic synthetic stories; no attack tools or network activity."""

from __future__ import annotations

import json
from pathlib import Path

from .common import LiaError, utc_text, write_json
from .normalize import parse_time

BASE_TIME = parse_time("2026-01-15T12:00:00.000000Z")[0]


def raw_event(
    index: int,
    seconds: float = 0,
    action: str = "auth.login",
    outcome: str = "failure",
    user: str | None = "demo-user",
    address: str | None = "192.0.2.10",
    **sections,
) -> dict:
    event = {
        "schema_version": "app-audit-v1",
        "event_id": f"event-{index:08d}",
        "timestamp": utc_text(BASE_TIME + round(seconds * 1000000)),
        "action": action,
        "outcome": outcome,
        "actor": {"user_id": user},
        "network": {"peer_ip": address},
    }
    event.update(sections)
    return event


def story(kind: str = "attack") -> list[dict]:
    if kind not in {"attack", "recovery", "incomplete"}:
        raise LiaError("unknown_demo_story")
    events = [raw_event(i, i * 10) for i in range(10)]
    session = {"session_id": "SYNTHETIC-SESSION-DO-NOT-LOG"} if kind != "incomplete" else {}
    events.append(raw_event(10, 100, outcome="success", auth=session))
    events.append(
        raw_event(
            11,
            120,
            action="auth.mfa.enroll",
            outcome="success",
            target={"user_id": "demo-user"},
            auth={**session, "device_ref": "demo-device-2"},
        )
    )
    return events


def write_input(directory: Path, events: list[dict], name: str = "app.jsonl", **source_options) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / name).open("w", encoding="utf-8", newline="\n") as stream:
        for event in events:
            stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    source = {
        "path": name,
        "format": "app-audit-v1",
        "source_id": "demo-audit",
        "tenant_id": "local",
        "application_id": "demo",
        "authority": "idp_audit",
        "platform_scope": "identity_provider",
        "declared_capabilities": [
            "auth.login.failure",
            "auth.login.success",
            "auth.mfa.challenge",
            "auth.mfa.enroll",
            "authz.denied",
            "http.request",
            "source.heartbeat",
        ],
        **source_options,
    }
    manifest = directory / "manifest.yml"
    write_json(manifest, {"schema": "lia-input/v1", "input_root": ".", "sources": [source]})
    return manifest


def recovery_context() -> dict:
    return {
        "id": "approved-recovery",
        "kind": "approved",
        "tenant_id": "local",
        "application_id": "demo",
        "user_id": "demo-user",
        "rule_id": "DET-006",
        "source": "synthetic-ticket",
        "author": "demo-owner",
        "reason": "Demonstration of independently recorded recovery approval",
        "created_at": "2026-01-14T00:00:00Z",
        "valid_from": "2026-01-15T11:00:00Z",
        "expires_at": "2026-01-15T13:00:00Z",
    }
