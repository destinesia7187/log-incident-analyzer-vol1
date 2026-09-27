import copy
import json
import socket

import pytest
from typer.testing import CliRunner

from lia.cli import app
from lia.common import LiaError, write_json
from lia.config import Config, parse_model
from lia.demo import raw_event, recovery_context, story, write_input
from lia.evaluation import metrics, replay
from lia.pipeline import compare, read_run, update_case

runner = CliRunner()


@pytest.mark.case("CLI-001")
def test_help():
    for arguments in [
        [],
        ["analyze"],
        ["demo"],
        ["validate-rules"],
        ["validate-config"],
        ["quality"],
        ["explain"],
        ["replay"],
        ["compare"],
        ["benchmark"],
        ["case"],
        ["case", "set-status"],
        ["case", "add-note"],
    ]:
        result = runner.invoke(app, arguments + ["--help"])
        assert result.exit_code == 0, result.output
        assert "Usage" in result.output


@pytest.mark.case("CLI-002", "CLI-003", "CLI-004")
@pytest.mark.parametrize("kind,expected", [("benign", 0), ("alert", 10), ("partial", 3)])
def test_analyze_codes(tmp_path, kind, expected):
    manifest = write_input(
        tmp_path / "input", [raw_event(0, outcome="success")] if kind == "benign" else story()
    )
    if kind == "partial":
        with (manifest.parent / "app.jsonl").open("a") as f:
            f.write("{broken}\n")
    result = runner.invoke(
        app,
        [
            "analyze",
            "--manifest",
            str(manifest),
            "--output",
            str(tmp_path / "out"),
            "--fail-on-alert",
            "--json",
        ],
    )
    assert result.exit_code == expected, result.output
    assert json.loads(result.stdout)["state"].startswith("completed")


@pytest.mark.case("CLI-005")
def test_config_error(tmp_path):
    config = tmp_path / "bad.yml"
    config.write_text("unknown: true")
    result = runner.invoke(app, ["validate-config", "--config", str(config)])
    assert result.exit_code == 2 and json.loads(result.stderr)["error"] == "invalid_config"


@pytest.mark.case("CLI-006")
def test_io_error(tmp_path):
    result = runner.invoke(
        app, ["analyze", "--manifest", str(tmp_path / "missing"), "--output", str(tmp_path / "out")]
    )
    assert result.exit_code == 4


@pytest.mark.case("CLI-007")
def test_require_complete(tmp_path):
    manifest = write_input(tmp_path / "input", [raw_event(0)])
    result = runner.invoke(
        app, ["analyze", "--manifest", str(manifest), "--output", str(tmp_path / "out"), "--require-complete"]
    )
    assert result.exit_code == 3 and (tmp_path / "out" / "quality.json").exists()


@pytest.mark.case("CLI-008")
def test_json_read_commands(pipeline):
    a, _, _, out = pipeline(story())
    cid = a["cases"][0]["id"]
    for command in [["quality", "--json"], ["explain", "--case", cid, "--json"]]:
        result = runner.invoke(app, command + ["--run", str(out)])
        assert result.exit_code == 0, result.output
        assert isinstance(json.loads(result.stdout), dict)
        assert result.stderr == ""


@pytest.mark.case("CLI-009")
def test_unicode_paths(tmp_path):
    manifest = write_input(tmp_path / "данные с пробелом", story())
    out = tmp_path / "результат анализа"
    result = runner.invoke(app, ["analyze", "--manifest", str(manifest), "--output", str(out)])
    assert result.exit_code == 0 and (out / "analysis.json").exists()


@pytest.mark.case("CLI-011")
def test_missing_case(pipeline):
    _, _, _, out = pipeline(story())
    for command in [["explain"], ["case", "add-note", "--text", "test", "--analyst", "local"]]:
        result = runner.invoke(app, command + ["--run", str(out), "--case", "UNKNOWN"])
        assert result.exit_code == 2 and "unknown_case" in result.stderr


@pytest.mark.case("CLI-012")
def test_dataset_compare(pipeline):
    a, _, _, out1 = pipeline(story())
    b, _, _, out2 = pipeline([raw_event(0)])
    with pytest.raises(LiaError, match="dataset_mismatch"):
        compare(a, b)
    identical = compare(a, copy.deepcopy(a))
    assert not identical["added_alerts"] and not identical["removed_alerts"]


@pytest.mark.case("REP-001")
def test_public_schemas(pipeline):
    import jsonschema

    from lia.schemas import SCHEMAS

    _, _, _, out = pipeline(story())
    for filename, schema in SCHEMAS.items():
        value = json.loads((out / filename).read_text(encoding="utf-8"))
        jsonschema.validate(value, schema)
    malformed = json.loads((out / "analysis.json").read_text())
    del malformed["event_count"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(malformed, SCHEMAS["analysis.json"])


@pytest.mark.case("REP-002")
def test_formats(pipeline):
    a, _, _, out = pipeline(story(), formats=["json", "markdown", "html"])
    for name in ["report.md", "report.html"]:
        text = (out / name).read_text(encoding="utf-8")
        for c in a["cases"]:
            assert c["id"] in text and c["priority"].upper() in text


@pytest.mark.case("REP-003")
def test_evidence(pipeline):
    a, _, _, _ = pipeline(story())
    ids = {e["uid"] for e in a["evidence"]}
    for c in a["cases"]:
        for fact in c["facts"]:
            assert set(fact["evidence_ids"]) <= ids and fact["evidence_ids"]
    assert len(ids) == 12


@pytest.mark.case("REP-004")
def test_truncation(pipeline):
    a, _, _, out = pipeline([raw_event(i, i) for i in range(75)], formats=["json", "markdown", "html"])
    assert len(a["evidence"]) == 75
    assert "truncated to 50" in (out / "report.html").read_text(encoding="utf-8")
    assert "truncated to 50" in (out / "report.md").read_text(encoding="utf-8")


@pytest.mark.case("REP-005")
def test_confidence(event, detect_events):
    good = [event(i, i) for i in range(10)]
    assert detect_events(good)[0][0]["confidence"] == "supported"
    good[-1].flags = ["time_uncertainty"]
    assert detect_events(good)[0][0]["confidence"] == "limited"


@pytest.mark.case("REP-006")
def test_html_static(pipeline):
    from html.parser import HTMLParser

    class Inspector(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []
            self.links = []

        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)
            self.links.extend(v for k, v in attrs if k in ("src", "href"))

    _, _, _, out = pipeline(story(), formats=["html"])
    parser = Inspector()
    text = (out / "report.html").read_text(encoding="utf-8")
    parser.feed(text)
    assert not {"script", "iframe", "form", "img"} & set(parser.tags)
    assert {"h1", "h2", "th", "nav"} <= set(parser.tags) and all(v.startswith("#") for v in parser.links)
    assert "@media print" in text


@pytest.mark.case("REP-007")
def test_notes_separate(pipeline):
    a, _, _, out = pipeline(story())
    cid = a["cases"][0]["id"]
    before = copy.deepcopy(a["cases"][0]["facts"])
    c = update_case(out, cid, "analyst", note="Unverified report from a caller")
    assert c["facts"] == before and c["notes"][0]["text"] == "Unverified report from a caller"


@pytest.mark.case("REP-008")
def test_metadata(pipeline):
    a, r, _, _ = pipeline(story())
    for name in ["manifest_hash", "config_hash", "rules_hash", "analysis_hash", "dataset_hash"]:
        assert len(r[name]) == 64
    assert r["duration_seconds"] >= 0 and r["parameters"]["config"]["limits"]["max_files"] == 100


@pytest.mark.case("E2E-001", "E2E-002", "E2E-003")
@pytest.mark.parametrize(
    "variant,expected,score",
    [
        ("attack", {"DET-001", "DET-003", "DET-006"}, 75),
        ("recovery", {"DET-001", "DET-003", "DET-006"}, 55),
        ("incomplete", {"DET-001", "DET-003"}, 60),
    ],
)
def test_cli_demo(tmp_path, variant, expected, score):
    out = tmp_path / variant
    result = runner.invoke(app, ["demo", "--variant", variant, "--output", str(out)])
    assert result.exit_code == 0, result.output
    a = read_run(out)
    assert {x["rule_id"] for x in a["alerts"]} == expected
    assert a["cases"][0]["score"] == score and a["cases"][0]["decision"] == "escalate"


@pytest.mark.case("E2E-004")
def test_nat_story(pipeline):
    events = [raw_event(i, i, user=f"employee-{i}") for i in range(10)]
    events += [raw_event(100 + i, 100 + i, user="target", address="198.51.100.1") for i in range(10)]
    a, _, _, _ = pipeline(events)
    assert len(a["cases"]) == 2
    assert {c["user_id"] for c in a["cases"]} == {None, "target"}


@pytest.mark.case("E2E-005")
def test_replay(tmp_path):
    scenarios = []
    for i in range(48):
        kind = "incomplete" if i % 3 == 2 else "attack"
        manifest = write_input(tmp_path / f"scenario-{i}", story(kind))
        scenarios.append(
            {
                "id": f"scenario-{i}",
                "manifest": str(manifest.relative_to(tmp_path)),
                "expected_rules": ["DET-001", "DET-003"] + (["DET-006"] if kind == "attack" else []),
                "forbidden_rules": ["DET-006"] if kind == "incomplete" else [],
            }
        )
    path = tmp_path / "suite.yml"
    write_json(path, {"schema": "lia-suite/v1", "scenarios": scenarios})
    result = replay(path, tmp_path / "runs")
    assert result["passed"] and len(result["scenarios"]) == 48


def evaluation_fixtures():
    a = {
        "id": "a",
        "rule_id": "DET-001",
        "tenant_id": "t",
        "application_id": "app",
        "user_id": "u",
        "start": 0,
        "end": 10,
        "evidence_ids": ["e"],
    }
    episode = {
        "id": "ep",
        "label": "attack",
        "tenant_id": "t",
        "application_id": "app",
        "entity_field": "user_id",
        "entity_value": "u",
        "start": 0,
        "end": 10,
        "primary_rules": ["DET-001"],
        "relevant_event_ids": ["e"],
    }
    return a, episode


@pytest.mark.case("E2E-006")
def test_matching_duplicates():
    a, e = evaluation_fixtures()
    m = metrics([a, {**a, "id": "b"}], [e, {**e, "id": "missed", "relevant_event_ids": ["other"]}])
    assert (m["tp"], m["fp"], m["fn"], m["duplicate_alerts"]) == (1, 1, 1, 1)


@pytest.mark.case("E2E-007")
def test_denominators():
    a, e = evaluation_fixtures()
    m = metrics([a], [e, {**e, "id": "missing", "eligible": False}])
    assert m["eligible_recall"] == 1 and m["end_to_end_recall"] == 0.5 and m["unassessed"] == 1


@pytest.mark.case("E2E-008")
def test_context_comparison(pipeline):
    a, _, _, _ = pipeline(story())
    b, _, _, _ = pipeline(story(), config=parse_model(Config, {"context": [recovery_context()]}))
    assert a["dataset_hash"] == b["dataset_hash"]
    diff = compare(a, b)
    assert diff["context_changed"] and not diff["added_alerts"] and not diff["removed_alerts"]
    assert len(a["alerts"]) == 3 and len(a["cases"]) == 1
    assert len(b["alerts"]) == 3 and b["cases"][0]["score"] == 55


@pytest.mark.case("SEC-016")
def test_offline_demo_replay(tmp_path, monkeypatch):
    def deny(*args, **kwargs):
        raise AssertionError("network used")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    assert runner.invoke(app, ["demo", "--output", str(tmp_path / "demo")]).exit_code == 0
    manifest = write_input(tmp_path / "input", story())
    suite = tmp_path / "suite.yml"
    write_json(
        suite,
        {
            "schema": "lia-suite/v1",
            "scenarios": [
                {"id": "one", "manifest": str(manifest.relative_to(tmp_path)), "expected_rules": ["DET-006"]}
            ],
        },
    )
    assert replay(suite, tmp_path / "replay")["passed"]
