import sqlite3
from pathlib import Path

import pytest

from lia.demo import story
from lia.pipeline import read_run, update_case


def test_review_recovers_after_export_rename_failure(pipeline, monkeypatch):
    analysis, _, _, output = pipeline(story(), formats=["json", "markdown", "html"])
    case = analysis["cases"][0]["id"]
    original = Path.replace

    def interrupted(self, target):
        if self.name == "report.html":
            raise OSError("simulated failed publication")
        return original(self, target)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "replace", interrupted)
        with pytest.raises(OSError):
            update_case(output, case, "reviewer", note="Owner verification pending")
    assert (output / ".review-pending.json").exists()
    recovered = read_run(output)
    assert recovered["cases"][0]["notes"][0]["text"] == "Owner verification pending"
    assert "Owner verification pending" in (output / "report.html").read_text(encoding="utf-8")
    assert not (output / ".review-pending.json").exists()
    assert not (output / ".review-stage").exists()
    with sqlite3.connect(output / "analysis.sqlite") as db:
        assert db.execute("SELECT COUNT(*) FROM case_notes").fetchone()[0] == 1
    assert read_run(output) == recovered


def test_review_uncommitted_stage_is_discarded(pipeline):
    from lia.common import sha_file, write_json

    analysis, _, _, output = pipeline(story())
    stage = output / ".review-stage"
    stage.mkdir()
    write_json(stage / "analysis.json", {"not_committed": True})
    write_json(
        output / ".review-pending.json",
        {"id": "not-committed", "files": {"analysis.json": sha_file(stage / "analysis.json")}},
    )
    assert read_run(output) == analysis
    assert not stage.exists()


def test_failed_review_render_preserves_original(pipeline, monkeypatch):
    from lia import pipeline as engine

    analysis, _, _, output = pipeline(story())
    case_id = analysis["cases"][0]["id"]
    original = (output / "analysis.json").read_bytes()

    def fail(*_):
        raise OSError("full disk")

    monkeypatch.setattr(engine, "export", fail)
    with pytest.raises(OSError):
        update_case(output, case_id, "reviewer", note="not committed")
    assert (output / "analysis.json").read_bytes() == original
    assert not (output / ".review-stage").exists()
    with sqlite3.connect(output / "analysis.sqlite") as db:
        assert db.execute("SELECT COUNT(*) FROM case_notes").fetchone()[0] == 0


def test_schema_rejects_missing_evidence_and_invalid_priority(pipeline):
    from copy import deepcopy

    from jsonschema import ValidationError, validate

    from lia.schemas import SCHEMAS

    analysis, _, _, _ = pipeline(story())
    validate(analysis, SCHEMAS["analysis.json"])
    bad = deepcopy(analysis)
    bad["alerts"][0]["evidence_ids"] = []
    with pytest.raises(ValidationError):
        validate(bad, SCHEMAS["analysis.json"])
    bad = deepcopy(analysis)
    bad["cases"][0]["score"] = 101
    with pytest.raises(ValidationError):
        validate(bad, SCHEMAS["analysis.json"])


def test_implicit_edges_and_duration_split():
    from test_triage_quality import fake_alert

    from lia.config import Config
    from lia.triage import assemble

    cases = assemble([fake_alert(1), fake_alert(2, start=20, end=30)], Config())
    assert cases[0]["edges"][0]["reason"] == "same_identity_time_window"
    cases = assemble(
        [fake_alert(1, start=0, end=3500000000), fake_alert(2, start=3500000001, end=3600000001)], Config()
    )
    assert len(cases) == 2
    assert cases[0]["related_reasons"][0]["reason"] == "case_duration_limit"
