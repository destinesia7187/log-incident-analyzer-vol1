"""Transactional batch analysis and case review operations."""

from __future__ import annotations

import json
import os
import secrets
import shutil
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import __version__
from .common import LiaError, canonical, digest, is_link, now_text, sha_file, write_json
from .config import Config, Manifest, load_yaml, manifest_hash, parse_model
from .detection import detect
from .ingest import ingest
from .reporting import export, shareable
from .rules import load_rules, validate_rules
from .storage import Store
from .triage import assemble


@contextmanager
def workspace(parent: Path) -> Iterator[tuple[bytes, Path]]:
    parent.mkdir(parents=True, exist_ok=True)
    for p in [parent, *parent.parents]:
        if p.exists() and is_link(p):
            raise LiaError("unsafe_output_link")
    private = parent / ".lia"
    if private.exists() and is_link(private):
        raise LiaError("unsafe_workspace_link")
    private.mkdir(exist_ok=True)
    lock = private / "writer.lock"
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise LiaError("workspace_busy", 4) from exc
    try:
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        keyfile = private / "session.key"
        if keyfile.exists() and is_link(keyfile):
            raise LiaError("unsafe_key_link")
        if not keyfile.exists():
            keyfile.write_bytes(secrets.token_bytes(32))
            keyfile.chmod(0o600)
        key = keyfile.read_bytes()
        if len(key) != 32:
            raise LiaError("invalid_workspace_key", 4)
        yield key, private
    finally:
        lock.unlink(missing_ok=True)


def analyze(
    manifest_path: Path,
    output: Path,
    config: Config | None = None,
    rules: list[dict] | None = None,
    formats: list[str] | None = None,
    require_complete: bool = False,
    fail_on_alert: bool = False,
    share: bool = False,
) -> tuple[dict, dict, int]:
    config = config or Config()
    rules = validate_rules(rules) if rules is not None else load_rules()
    if config.enabled_rules is not None:
        known = {r["id"] for r in rules}
        if not set(config.enabled_rules) <= known:
            raise LiaError("unknown_enabled_rule")
        rules = validate_rules([r for r in rules if r["id"] in config.enabled_rules])
    formats = formats or ["json", "markdown"]
    if not set(formats) <= {"json", "markdown", "html"}:
        raise LiaError("unsupported_output_format")
    manifest: Manifest = parse_model(Manifest, load_yaml(manifest_path))
    output = output.absolute()
    input_root = (manifest_path.parent / manifest.input_root).resolve()
    if (
        output.exists()
        or output.resolve().is_relative_to(input_root)
        or input_root.is_relative_to(output.resolve())
    ):
        raise LiaError("unsafe_or_existing_output")
    start = time.perf_counter()
    phase_timings = {}
    run: dict[str, Any] = {
        "schema_version": "1.0",
        "program_version": __version__,
        "python": sys.version.split()[0],
        "created_at": now_text(),
        "state": "created",
        "manifest_hash": manifest_hash(manifest),
        "config_hash": digest(config.model_dump()),
        "rules_hash": digest(rules),
        "parameters": {"config": config.model_dump(mode="json"), "formats": formats, "shareable": share},
    }
    staging = output.parent / (".lia-stage-" + secrets.token_hex(8))
    store = None
    try:
        with workspace(output.parent) as (key, _):
            run["pseudonym_key_id"] = digest(key.hex())[:16]
            staging.mkdir()
            store = Store(staging / "analysis.sqlite")
            run["state"] = "ingesting"
            counts, findings, artifacts = ingest(store, manifest, manifest_path, config, key)
            phase_timings["ingest_seconds"] = time.perf_counter() - start
            phase_start = time.perf_counter()
            run["state"] = "analyzing"
            alerts, quality, detector_findings = detect(store.events(), rules, config, manifest.sources)
            findings.extend(detector_findings)
            cases = assemble(alerts, config)
            phase_timings["detection_triage_seconds"] = time.perf_counter() - phase_start
            phase_start = time.perf_counter()
            used = sorted({uid for a in alerts for uid in a["evidence_ids"]})
            evidence = [store.event(uid).payload() for uid in used]
            dataset_hash = digest({"artifacts": artifacts, "manifest": run["manifest_hash"]})
            analysis = {
                "schema_version": "1.0",
                "program_version": __version__,
                "dataset_hash": dataset_hash,
                "rules_hash": run["rules_hash"],
                "config_hash": run["config_hash"],
                "event_count": counts["accepted_unique"],
                "alerts": alerts,
                "cases": cases,
                "evidence": evidence,
                "quality": quality,
                "quality_findings": sorted(findings, key=canonical),
            }
            store.save_results(alerts, cases, findings)
            store.close()
            store = None
            if share:
                analysis = shareable(analysis, key)
                # A public share bundle must not include the private SQLite database.
                (staging / "analysis.sqlite").unlink()
            export(analysis, staging, formats)
            phase_timings["persistence_export_seconds"] = time.perf_counter() - phase_start
            if (
                sum(p.stat().st_size for p in staging.iterdir() if p.is_file())
                > config.limits.workspace_bytes
            ):
                raise LiaError("workspace_size_limit", 4)
            partial = bool(counts["quarantined_rows"] or counts["conflicted_rows"])
            incomplete = any(q["status"] != "ready" for q in quality)
            exit_code = (
                3 if partial or require_complete and incomplete else 10 if fail_on_alert and alerts else 0
            )
            run.update(
                {
                    "state": "completed_with_warnings" if partial or findings or incomplete else "completed",
                    "duration_seconds": time.perf_counter() - start,
                    "phase_timings": phase_timings,
                    "counts": counts,
                    "artifacts": artifacts,
                    "dataset_hash": dataset_hash,
                    "analysis_hash": digest(analysis),
                    "exit_code": exit_code,
                }
            )
            if share:
                run["parameters"] = {"shareable": True, "formats": formats}
            write_json(staging / "run.json", run)
            staging.rename(output)
            return analysis, run, exit_code
    except (KeyboardInterrupt, LiaError, OSError, sqlite3.Error) as exc:
        if store:
            store.close()
        code = (
            130 if isinstance(exc, KeyboardInterrupt) else exc.exit_code if isinstance(exc, LiaError) else 4
        )
        error = (
            "interrupted"
            if isinstance(exc, KeyboardInterrupt)
            else exc.code
            if isinstance(exc, LiaError)
            else "storage_io_error"
        )
        # Staging belongs exclusively to this invocation; never touch input/user files.
        if staging.exists():
            shutil.rmtree(staging)
        if not output.exists():
            try:
                output.mkdir(parents=True)
                run.update(
                    {"state": "interrupted" if code == 130 else "failed", "error": error, "exit_code": code}
                )
                write_json(output / "run.json", run)
            except OSError:
                pass
        raise LiaError(error, code) from exc


def read_run(directory: Path) -> dict:
    if (directory / ".review-pending.json").exists():
        with workspace(directory.parent):
            recover_review(directory)
    try:
        return json.loads((directory / "analysis.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise LiaError("run_unavailable", 4) from exc


def recover_review(directory: Path) -> None:
    """Complete an interrupted committed review, or discard an uncommitted stage.

    The caller must hold the workspace writer lock. SQLite is the commit authority.
    """
    journal = directory / ".review-pending.json"
    if not journal.exists():
        return
    stage = directory / ".review-stage"
    if is_link(journal) or is_link(stage):
        raise LiaError("unsafe_review_link", 4)
    pending = json.loads(journal.read_text(encoding="utf-8"))
    allowed = {"analysis.json", "quality.json", "run.json", "report.md", "report.html"}
    if not set(pending["files"]) <= allowed:
        raise LiaError("invalid_review_journal", 4)
    db = sqlite3.connect(directory / "analysis.sqlite")
    try:
        committed = db.execute("SELECT 1 FROM review_commits WHERE id=?", (pending["id"],)).fetchone()
    finally:
        db.close()
    for name, expected in pending["files"].items():
        source, target = stage / name, directory / name
        if (source.exists() and is_link(source)) or (target.exists() and is_link(target)):
            raise LiaError("unsafe_review_link", 4)
        if committed:
            candidate = source if source.exists() else target
            if sha_file(candidate) != expected:
                raise LiaError("review_integrity_error", 4)
            if source.exists():
                source.replace(target)
        elif source.exists():
            source.unlink()
    if stage.exists():
        stage.rmdir()
    journal.unlink()


def update_case(
    directory: Path,
    case_id: str,
    analyst: str,
    status: str | None = None,
    reason: str = "",
    verdict: str | None = None,
    note: str | None = None,
) -> dict:
    if not analyst.strip() or len(analyst) > 256 or len(note or reason) > 4096:
        raise LiaError("invalid_review_input")
    with workspace(directory.parent):
        if not (directory / "analysis.sqlite").is_file():
            raise LiaError("private_database_required")
        recover_review(directory)
        analysis = read_run(directory)
        case = next((c for c in analysis["cases"] if c["id"] == case_id), None)
        if case is None:
            raise LiaError("unknown_case")
        previous = case["status"]
        if status:
            transitions = {
                "new": {"in_review"},
                "in_review": {"escalated", "closed"},
                "escalated": {"closed", "in_review"},
                "closed": {"in_review"},
            }
            if status not in transitions[previous]:
                raise LiaError("invalid_transition")
            if status == "closed" and (
                not reason.strip()
                or verdict not in {"benign_activity", "false_positive", "confirmed_incident", "inconclusive"}
            ):
                raise LiaError("closure_reason_required")
            entry = {
                "from": previous,
                "to": status,
                "analyst": analyst,
                "time": now_text(),
                "reason": reason,
                "verdict": verdict,
            }
            case["status"] = status
            case["history"].append(entry)
        elif note is not None and note.strip():
            entry = {"analyst": analyst, "time": now_text(), "text": note}
            case["notes"].append(entry)
        else:
            raise LiaError("review_action_required")
        store = Store(directory / "analysis.sqlite")
        created_stage = False
        try:
            formats = ["json", "markdown"] + (["html"] if (directory / "report.html").exists() else [])
            stage = directory / ".review-stage"
            if stage.exists():
                raise LiaError("review_stage_exists", 4)
            stage.mkdir()
            created_stage = True
            export(analysis, stage, formats)
            run = json.loads((directory / "run.json").read_text(encoding="utf-8"))
            run["reviewed_analysis_hash"] = digest(analysis)
            write_json(stage / "run.json", run)
            pending = {"id": secrets.token_hex(16), "files": {p.name: sha_file(p) for p in stage.iterdir()}}
            write_json(directory / ".review-pending.json", pending)
            with store.db:
                store.db.execute("UPDATE cases SET payload=? WHERE id=?", (canonical(case), case_id))
                table = "case_history" if status else "case_notes"
                store.db.execute(
                    f"INSERT INTO {table}(case_id,payload) VALUES(?,?)", (case_id, canonical(entry))
                )
                store.db.execute("INSERT INTO review_commits VALUES(?)", (pending["id"],))
            recover_review(directory)
            return case
        finally:
            store.close()
            if created_stage and not (directory / ".review-pending.json").exists() and stage.exists():
                if stage.resolve().parent != directory.resolve() or is_link(stage):
                    raise LiaError("unsafe_review_link", 4)
                shutil.rmtree(stage)


def compare(baseline: dict, candidate: dict) -> dict:
    if baseline["dataset_hash"] != candidate["dataset_hash"]:
        raise LiaError("dataset_mismatch")
    before = {a["id"] for a in baseline["alerts"]}
    after = {a["id"] for a in candidate["alerts"]}
    return {
        "schema_version": "1.0",
        "dataset_hash": baseline["dataset_hash"],
        "added_alerts": sorted(after - before),
        "removed_alerts": sorted(before - after),
        "case_count_before": len(baseline["cases"]),
        "case_count_after": len(candidate["cases"]),
        "rules_changed": baseline["rules_hash"] != candidate["rules_hash"],
        "context_changed": baseline["config_hash"] != candidate["config_hash"],
    }
