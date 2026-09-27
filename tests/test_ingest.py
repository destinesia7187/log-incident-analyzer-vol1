import copy
import gzip
import json

import pytest

from lia.common import LiaError, write_json
from lia.config import Config, Limits
from lia.demo import raw_event, write_input
from lia.pipeline import analyze
from lia.storage import Store


def setup_bytes(tmp_path, content, fmt="app-audit-v1", filename="app.jsonl"):
    manifest = write_input(tmp_path / "input", [])
    doc = json.loads(manifest.read_text())
    doc["sources"][0].update(format=fmt, path=filename)
    write_json(manifest, doc)
    (manifest.parent / filename).write_bytes(content)
    return manifest, tmp_path / "out"


def jl(events):
    return ("\n".join(json.dumps(e) for e in events) + "\n").encode()


@pytest.mark.case("ING-001")
def test_app_rows(pipeline):
    a, r, code, out = pipeline([raw_event(i, i) for i in range(3)])
    assert code == 0 and r["counts"]["accepted_unique"] == 3 and r["counts"]["quarantined_rows"] == 0
    store = Store(out / "analysis.sqlite")
    try:
        assert sorted(e.line for e in store.events()) == [1, 2, 3]
    finally:
        store.close()


@pytest.mark.case("ING-002")
def test_nginx_json(tmp_path):
    raw = {"timestamp": "2026-01-15T12:00:00Z", "http": {"method": "GET", "path": '/a"b', "status": 200}}
    m, o = setup_bytes(tmp_path, jl([raw]), "nginx-json-v1")
    _, r, _ = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 1
    s = Store(o / "analysis.sqlite")
    try:
        assert next(s.events()).get("http.path") == '/a"b'
    finally:
        s.close()


@pytest.mark.case("ING-003")
def test_combined(tmp_path):
    line = b'192.0.2.1 - - [15/Jan/2026:12:00:00 +0000] "GET /login HTTP/1.1" 200 10 "-" "agent"\n'
    m, o = setup_bytes(tmp_path, line, "nginx-combined-v1")
    _, r, _ = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 1
    s = Store(o / "analysis.sqlite")
    try:
        e = next(s.events())
        assert e.get("event.action") == "http.request" and e.get("http.status") == 200
    finally:
        s.close()


@pytest.mark.case("ING-004")
def test_gzip(tmp_path):
    m, o = setup_bytes(
        tmp_path, gzip.compress(jl([raw_event(i, i) for i in range(100)])), filename="app.jsonl.gz"
    )
    _, r, _ = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 100


@pytest.mark.case("ING-005", "TIM-011")
def test_multi_file_order(tmp_path):
    m, o = setup_bytes(tmp_path, jl([raw_event(i, i) for i in range(3)]))
    doc = json.loads(m.read_text())
    second = copy.deepcopy(doc["sources"][0])
    second["path"] = "second.jsonl"
    (m.parent / "second.jsonl").write_bytes(jl([raw_event(i, i) for i in range(3, 6)]))
    doc["sources"].append(second)
    write_json(m, doc)
    a, r, _ = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 6
    doc["sources"].reverse()
    write_json(m, doc)
    b, r2, _ = analyze(m, tmp_path / "out2")
    assert r["analysis_hash"] == r2["analysis_hash"]


@pytest.mark.case("ING-006")
def test_empty(tmp_path):
    m, o = setup_bytes(tmp_path, b"")
    a, r, code = analyze(m, o)
    assert r["counts"]["rows_seen"] == 0 and not a["alerts"] and code == 0
    assert all(q["status"] == "no_data" for q in a["quality"])


@pytest.mark.case("ING-007")
def test_blanks(tmp_path):
    m, o = setup_bytes(tmp_path, jl([raw_event(0)]) + b"\n\n\n" + jl([raw_event(1)]))
    _, r, _ = analyze(m, o)
    assert r["counts"]["blank_rows"] == 3 and r["counts"]["accepted_unique"] == 2
    s = Store(o / "analysis.sqlite")
    try:
        assert sorted(e.line for e in s.events()) == [1, 5]
    finally:
        s.close()


@pytest.mark.case("ING-008")
def test_bom(tmp_path):
    m, o = setup_bytes(tmp_path, b"\xef\xbb\xbf" + jl([raw_event(0)]) + b"\xef\xbb\xbf" + jl([raw_event(1)]))
    _, r, code = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 1 and r["counts"]["quarantined_rows"] == 1 and code == 3


@pytest.mark.case("ING-009", "ING-010")
@pytest.mark.parametrize("bad", [b"\xff\xfe\n", b'{"incomplete":\n'])
def test_bad_line(tmp_path, bad):
    m, o = setup_bytes(tmp_path, jl([raw_event(0)]) + bad + jl([raw_event(1)]))
    _, r, code = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 2 and r["counts"]["quarantined_rows"] == 1 and code == 3
    assert r["state"] == "completed_with_warnings"


@pytest.mark.case("ING-011")
def test_unknown_format(tmp_path):
    m, o = setup_bytes(tmp_path, b"")
    doc = json.loads(m.read_text())
    doc["sources"][0]["format"] = "unknown"
    write_json(m, doc)
    with pytest.raises(LiaError) as err:
        analyze(m, o)
    assert err.value.exit_code == 2 and not o.exists()


@pytest.mark.case("ING-012")
def test_truncated(tmp_path):
    m, o = setup_bytes(tmp_path, gzip.compress(jl([raw_event(0)]))[:-4], filename="app.gz")
    with pytest.raises(LiaError) as err:
        analyze(m, o)
    assert err.value.exit_code == 4 and not (o / "analysis.json").exists()


@pytest.mark.case("ING-013")
def test_bomb(tmp_path):
    m, o = setup_bytes(tmp_path, gzip.compress(b"a" * (11 * 1024**2)), filename="app.gz")
    with pytest.raises(LiaError, match="gzip_ratio_limit"):
        analyze(m, o)
    assert not (o / "analysis.json").exists()


@pytest.mark.case("ING-014")
def test_line_limit(tmp_path):
    raw = raw_event(0)
    raw["padding"] = ""
    overhead = len(json.dumps(raw).encode())
    raw["padding"] = "a" * (262144 - overhead)
    first = json.dumps(raw).encode()
    assert len(first) == 262144
    m, o = setup_bytes(tmp_path, first + b"\n" + first + b" \n")
    _, r, code = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 1 and r["counts"]["quarantined_rows"] == 1 and code == 3


@pytest.mark.case("ING-015")
def test_file_limit(tmp_path):
    m, o = setup_bytes(tmp_path, jl([raw_event(0)]))
    doc = json.loads(m.read_text())
    base = doc["sources"][0]
    doc["sources"] = []
    for i in range(100):
        name = f"f{i}.jsonl"
        (m.parent / name).write_bytes(jl([raw_event(i, i)]))
        doc["sources"].append({**base, "path": name})
    write_json(m, doc)
    _, r, _ = analyze(m, o)
    assert r["counts"]["accepted_unique"] == 100
    doc["sources"].append({**base, "path": "missing.jsonl"})
    write_json(m, doc)
    with pytest.raises(LiaError, match="file_count_limit"):
        analyze(m, tmp_path / "out2")


@pytest.mark.case("ING-016")
def test_input_limit(tmp_path):
    data = jl([raw_event(0)])
    m, o = setup_bytes(tmp_path, data)
    _, r, _ = analyze(m, o, Config(limits=Limits(input_bytes=len(data))))
    with pytest.raises(LiaError, match="input_size_limit"):
        analyze(m, tmp_path / "out2", Config(limits=Limits(input_bytes=len(data) - 1)))


@pytest.mark.case("ING-017")
def test_missing_file(tmp_path):
    m, o = setup_bytes(tmp_path, b"")
    (m.parent / "app.jsonl").unlink()
    with pytest.raises(LiaError, match="input_missing"):
        analyze(m, o)
    assert not (o / "analysis.json").exists()


@pytest.mark.case("ING-018")
def test_changing_file(tmp_path, monkeypatch):
    from lia import ingest as module

    original = module.sha_file
    calls = [0]

    def changed(path):
        calls[0] += 1
        return original(path) if calls[0] == 1 else "changed"

    monkeypatch.setattr(module, "sha_file", changed)
    m, o = setup_bytes(tmp_path, jl([raw_event(0)]))
    with pytest.raises(LiaError, match="input_changed"):
        analyze(m, o)


@pytest.mark.case("ING-019")
@pytest.mark.parametrize(
    "name,data", [("app.zip", b"PKfake"), ("app.gz", gzip.compress(b"one\n") + gzip.compress(b"two\n"))]
)
def test_archives(tmp_path, name, data):
    m, o = setup_bytes(tmp_path, data, filename=name)
    with pytest.raises(LiaError):
        analyze(m, o)
    assert not (o / "analysis.json").exists()


@pytest.mark.case("ING-020")
def test_accounting(tmp_path):
    data = jl([raw_event(i, i) for i in range(5)]) + jl([raw_event(0), raw_event(1, 1)]) + b"{bad}\n{bad}\n\n"
    m, o = setup_bytes(tmp_path, data)
    _, r, _ = analyze(m, o)
    c = r["counts"]
    assert [c[k] for k in ["accepted_unique", "duplicate_rows", "quarantined_rows", "blank_rows"]] == [
        5,
        2,
        2,
        1,
    ]
    assert c["rows_seen"] == 10
