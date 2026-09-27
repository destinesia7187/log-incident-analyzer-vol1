import json
import socket
import sqlite3

import pytest

from lia.common import LiaError, safe_file, sha_file, terminal_safe, write_json
from lia.config import Config, Limits, load_yaml
from lia.demo import raw_event, story, write_input
from lia.normalize import normalize
from lia.pipeline import analyze, workspace
from lia.reporting import md_escape
from lia.storage import Store


@pytest.mark.case("SEC-001")
def test_html_escape(pipeline):
    events = story()
    payload = "<script>CANARY()</script><img src=x onerror=CANARY()>"
    for e in events:
        e["actor"]["user_id"] = payload
    events[-1]["target"]["user_id"] = payload
    a, _, _, out = pipeline(events, formats=["json", "markdown", "html"])
    text = (out / "report.html").read_text(encoding="utf-8")
    assert "<script>" not in text and "<img src=x" not in text
    assert "&lt;script&gt;" in text and len(a["cases"]) == 1


@pytest.mark.case("SEC-002")
def test_markdown_escape():
    text = md_escape("<script>x</script>\n# fake [link](https://evil.test)")
    assert "<script>" not in text and "\n#" not in text and "\\[link\\]" in text


@pytest.mark.case("SEC-003")
def test_terminal_escape():
    assert terminal_safe("a\x1b[31mb\x1b]52;c;evil\x07c") == "abc"


@pytest.mark.case("SEC-004")
def test_sql_parameters(pipeline):
    user = "'; DROP TABLE events;--"
    _, _, _, out = pipeline([raw_event(0, user=user)])
    s = Store(out / "analysis.sqlite")
    try:
        assert next(s.events()).get("actor.user_id") == user
    finally:
        s.close()


@pytest.mark.case("SEC-005", "SEC-006")
@pytest.mark.parametrize(
    "text", ["!!python/object/apply:os.system [echo compromised]", "a: &a [1,2]\nb: [*a,*a]"]
)
def test_yaml_execution(tmp_path, text):
    p = tmp_path / "x.yml"
    p.write_text(text)
    with pytest.raises(LiaError):
        load_yaml(p)


@pytest.mark.case("SEC-007")
def test_json_depth(pipeline):
    nested = {}
    for _ in range(17):
        nested = {"x": nested}
    _, r, code, _ = pipeline([{**raw_event(0), "extra": nested}, raw_event(1)])
    assert code == 3 and r["counts"]["accepted_unique"] == 1 and r["counts"]["quarantined_rows"] == 1


@pytest.mark.case("SEC-008")
@pytest.mark.parametrize("relative", ["../outside.jsonl", "/outside.jsonl", "C:\\outside.jsonl"])
def test_traversal(tmp_path, relative):
    with pytest.raises(LiaError):
        safe_file(tmp_path, relative)


@pytest.mark.case("SEC-009")
def test_symlink_guard(tmp_path, monkeypatch):
    from lia import common

    target = tmp_path / "entry"
    target.write_text("not a log")
    original = common.is_link
    monkeypatch.setattr(common, "is_link", lambda p: p == target or original(p))
    with pytest.raises(LiaError, match="unsafe_link"):
        safe_file(tmp_path, "entry")


@pytest.mark.case("SEC-010", "CLI-010")
def test_output_guard(tmp_path):
    manifest = write_input(tmp_path / "input", story())
    before = sha_file(manifest.parent / "app.jsonl")
    with pytest.raises(LiaError):
        analyze(manifest, manifest.parent)
    out = tmp_path / "existing"
    out.mkdir()
    (out / "keep").write_text("keep")
    with pytest.raises(LiaError):
        analyze(manifest, out)
    assert (out / "keep").read_text() == "keep" and sha_file(manifest.parent / "app.jsonl") == before


@pytest.mark.case("SEC-011", "SEC-012", "SEC-013")
def test_secret_outputs(tmp_path):
    events = story()
    for e in events:
        e["password"] = "PASSWORD_CANARY"
        e["http"] = {
            "path": "/login?token=QUERY_CANARY",
            "Authorization": "BEARER_CANARY",
            "cookie": "COOKIE_CANARY",
        }
        e["auth"] = {**e.get("auth", {}), "session_id": "SESSION_CANARY"}
    manifest = write_input(tmp_path / "input", events)
    with (manifest.parent / "app.jsonl").open("ab") as f:
        f.write(b'{"broken":"BROKEN_CANARY"\n')
    out = tmp_path / "out"
    a, r, code = analyze(manifest, out, formats=["json", "markdown", "html"])
    assert code == 3
    for p in out.iterdir():
        if p.is_file():
            data = p.read_bytes()
            for secret in [
                b"PASSWORD_CANARY",
                b"QUERY_CANARY",
                b"BEARER_CANARY",
                b"COOKIE_CANARY",
                b"SESSION_CANARY",
                b"BROKEN_CANARY",
            ]:
                assert secret not in data, (p.name, secret)


@pytest.mark.case("SEC-014", "SEC-015")
def test_session_hmac(source):
    raw = raw_event(0, auth={"session_id": "SYNTHETIC_SECRET"})
    a = normalize(raw, source, Config(), b"a" * 32)
    b = normalize(raw, source, Config(), b"a" * 32)
    c = normalize(raw, source, Config(), b"b" * 32)
    assert a.get("auth.session_ref") == b.get("auth.session_ref") != c.get("auth.session_ref")
    assert "SYNTHETIC_SECRET" not in str(a.payload())


@pytest.mark.case("SEC-016", "SEC-017")
def test_offline_ssrf(pipeline, monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Network attempt")

    monkeypatch.setattr(socket, "socket", denied)
    monkeypatch.setattr(socket, "getaddrinfo", denied)
    events = story()
    events[0]["http"] = {"path": "http://169.254.169.254/latest/meta-data"}
    a, _, _, _ = pipeline(events)
    assert len(a["alerts"]) == 3


@pytest.mark.case("SEC-018")
def test_group_cap(event, detect_events):
    values = [event(i, i, user=f"user{i}") for i in range(4)]
    with pytest.raises(LiaError, match="active_group_limit"):
        detect_events(values, config=Config(limits=Limits(max_groups=3)))


@pytest.mark.case("SEC-019")
def test_shareable(pipeline):
    a, r, _, out = pipeline(story(), share=True, formats=["json", "markdown", "html"])
    for p in out.iterdir():
        text = p.read_text(encoding="utf-8")
        assert "demo-user" not in text and "192.0.2.10" not in text and "demo-device-2" not in text
    assert not (out / "analysis.sqlite").exists() and a["shareable"]
    assert a["cases"][0]["user_id"].startswith("ref-")


@pytest.mark.case("STO-001", "STO-002")
def test_copied_artifact(tmp_path):
    manifest = write_input(tmp_path / "input", [raw_event(0)])
    (manifest.parent / "copy.jsonl").write_bytes((manifest.parent / "app.jsonl").read_bytes())
    doc = json.loads(manifest.read_text())
    doc["sources"].append({**doc["sources"][0], "path": "copy.jsonl"})
    write_json(manifest, doc)
    a, r, _ = analyze(manifest, tmp_path / "out")
    assert r["counts"]["accepted_unique"] == 1 and r["counts"]["reused_artifacts"] == 1


@pytest.mark.case("STO-003")
def test_web_duplicates(tmp_path):
    raw = {"timestamp": "2026-01-15T12:00:00Z", "http": {"method": "GET", "path": "/", "status": 200}}
    manifest = write_input(tmp_path / "input", [raw], format="nginx-json-v1")
    original = (manifest.parent / "app.jsonl").read_bytes()
    (manifest.parent / "copy.jsonl").write_bytes(original + b"\n")
    doc = json.loads(manifest.read_text())
    doc["sources"].append({**doc["sources"][0], "path": "copy.jsonl"})
    write_json(manifest, doc)
    a, r, _ = analyze(manifest, tmp_path / "out")
    assert r["counts"]["accepted_unique"] == 2
    assert any(f["code"] == "possible_duplicate_web_records" for f in a["quality_findings"])


@pytest.mark.case("STO-004")
def test_id_conflict(pipeline):
    a, r, code, _ = pipeline([raw_event(0), raw_event(0, outcome="success")])
    assert a["event_count"] == 0 and r["counts"]["conflicted_rows"] == 2 and code == 3


@pytest.mark.case("STO-005")
def test_foreign_key(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            s.db.execute("INSERT INTO alert_events VALUES(?,?)", ("none", "none"))
    finally:
        s.close()


@pytest.mark.case("STO-006")
def test_transaction_rollback(tmp_path):
    s = Store(tmp_path / "db.sqlite")
    try:
        with pytest.raises(sqlite3.IntegrityError):
            with s.db:
                s.db.execute("INSERT INTO alerts VALUES(?,?)", ("a", "{}"))
                s.db.execute("INSERT INTO alert_events VALUES(?,?)", ("a", "missing"))
        assert s.db.execute("SELECT COUNT(*) FROM alerts").fetchone()[0] == 0
    finally:
        s.close()


@pytest.mark.case("STO-007", "STO-008")
@pytest.mark.parametrize("error", [OSError(28, "No space"), PermissionError("Denied")])
def test_storage_fault(tmp_path, monkeypatch, error):
    from lia import pipeline

    manifest = write_input(tmp_path / "input", story())
    out = tmp_path / "out"

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(pipeline, "export", fail)
    with pytest.raises(LiaError) as exc:
        pipeline.analyze(manifest, out)
    assert exc.value.exit_code == 4 and not (out / "analysis.json").exists()
    assert json.loads((out / "run.json").read_text())["state"] == "failed"


@pytest.mark.case("STO-009")
@pytest.mark.parametrize("phase", ["ingest", "detect"])
def test_interrupted(tmp_path, monkeypatch, phase):
    from lia import pipeline

    manifest = write_input(tmp_path / "input", story())
    out = tmp_path / "out"

    def interrupt(*args, **kwargs):
        raise KeyboardInterrupt()

    monkeypatch.setattr(pipeline, phase, interrupt)
    with pytest.raises(LiaError) as exc:
        pipeline.analyze(manifest, out)
    assert exc.value.exit_code == 130 and not (out / "analysis.json").exists()
    assert json.loads((out / "run.json").read_text())["state"] == "interrupted"


@pytest.mark.case("STO-010")
def test_writer_lock(tmp_path):
    with workspace(tmp_path):
        with pytest.raises(LiaError, match="workspace_busy"):
            with workspace(tmp_path):
                pass
    assert not (tmp_path / ".lia" / "writer.lock").exists()


@pytest.mark.case("STO-011")
def test_schema_version(tmp_path):
    p = tmp_path / "db.sqlite"
    s = Store(p)
    s.close()
    connection = sqlite3.connect(p)
    connection.execute("PRAGMA user_version=99")
    connection.close()
    with pytest.raises(LiaError, match="unsupported_database_version"):
        Store(p)


@pytest.mark.case("STO-012")
def test_artifact_integrity(tmp_path):
    p = tmp_path / "data"
    p.write_bytes(b"original")
    before = sha_file(p)
    p.write_bytes(b"changed")
    assert sha_file(p) != before
