import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from lia.benchmark import run_benchmark
from lia.common import LiaError, sha_file, write_json
from lia.config import Config, Limits
from lia.demo import story
from lia.evaluation import replay

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.case("PERF-003", "PERF-006")
@pytest.mark.performance
@pytest.mark.parametrize("size", [100000, 1000000])
def test_recorded_benchmark(size):
    env = os.environ.get("LIA_BENCHMARK_DIR")
    if not env:
        pytest.skip("Set LIA_BENCHMARK_DIR to the directory containing recorded 100k/million measurements.")
    filename = "benchmark-100k-final" if size == 100000 else "benchmark-million-final"
    path = Path(env) / filename / "benchmark.json"
    if not path.exists():
        pytest.skip("Performance run has not completed: " + str(path))
    report = json.loads(path.read_text())
    assert len(report["runs"]) == 5 and report["profile"]["warmups"] == 1
    assert report["peak_rss_bytes"] <= (1 if size == 100000 else 2) * 1024**3
    assert all(
        r["counts"]["rows_seen"] == size and r["counts"]["quarantined_rows"] == size // 100
        for r in report["runs"]
    )
    assert all(r["disk_bytes"] <= 6 * report["input_bytes"] + 100 * 1024**2 for r in report["runs"])


@pytest.mark.case("PERF-001", "PERF-002")
@pytest.mark.performance
def test_fixed_linux_time_acceptance():
    if os.environ.get("LIA_FIXED_RUNNER") != "linux-4vcpu-8gib-ssd":
        pytest.skip(
            "Absolute-time acceptance requires the documented fixed Linux 4 vCPU / 8 GiB / SSD runner."
        )
    root = Path(os.environ["LIA_BENCHMARK_DIR"])
    for name, limit in [("benchmark-100k-final", 30), ("benchmark-million-final", 180)]:
        report = json.loads((root / name / "benchmark.json").read_text())
        assert report["platform"].startswith("Linux")
        assert len(report["runs"]) == 5 and report["median_seconds"] <= limit


@pytest.mark.case("PERF-004")
def test_high_cardinality_limit(event, detect_events):
    events = [event(i, i / 100, user=f"u{i}") for i in range(501)]
    with pytest.raises(LiaError, match="active_group_limit"):
        detect_events(events, Config(limits=Limits(max_groups=500)))


@pytest.mark.case("PERF-005")
def test_dense_count(event, detect_events):
    events = [event(i, i * 0.01) for i in range(10000)]
    started = time.perf_counter()
    alerts = detect_events(events)[0]
    matching = [a for a in alerts if a["rule_id"] == "DET-001"]
    assert len(matching) == 1 and len(matching[0]["evidence_ids"]) == 10000
    assert len(set(matching[0]["evidence_ids"])) == 10000
    assert time.perf_counter() - started < 20


@pytest.mark.case("PERF-007")
def test_html_volume(tmp_path):
    from test_triage_quality import fake_alert

    from lia.reporting import export
    from lia.triage import assemble

    alerts = [fake_alert(i, user=f"user{i}") for i in range(1000)]
    cases = assemble(alerts, Config())
    evidence = [
        {
            "uid": f"e{i}",
            "time": 0,
            "fields": {"event.action": "auth.login", "event.outcome": "failure"},
            "source_id": "test",
            "line": i + 1,
        }
        for i in range(1000)
    ]
    payload = {
        "schema_version": "1.0",
        "event_count": 1000,
        "alerts": alerts,
        "cases": cases,
        "evidence": evidence,
        "quality": [],
        "quality_findings": [],
    }
    export(payload, tmp_path, ["html"])
    text = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert (
        text.count("<article ") == 1000
        and len(json.loads((tmp_path / "analysis.json").read_text())["cases"]) == 1000
    )


@pytest.mark.case("PERF-008")
def test_regression_policy():
    from lia.benchmark import regression

    base = {"dataset_sha256": "same", "profile": {"events": 100}, "median_seconds": 10, "platform": "fixed"}
    assert regression(base, {**base, "median_seconds": 12.01})["requires_review"]
    assert not regression(base, {**base, "median_seconds": 11.9})["requires_review"]
    with pytest.raises(LiaError):
        regression(base, {**base, "dataset_sha256": "other"})


@pytest.mark.case("CI-001")
@pytest.mark.delivery
def test_clean_wheel(tmp_path):
    python = os.environ.get("LIA_CLEAN_PYTHON")
    if not python:
        pytest.skip("Set LIA_CLEAN_PYTHON after installing the built wheel in a fresh environment.")
    env = os.environ.copy()
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [python, "-m", "lia.cli", "demo", "--output", str(tmp_path / "demo")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["alerts"] == 3


@pytest.mark.case("CI-002")
def test_runtime_contract(pipeline):
    a, _, _, _ = pipeline(story())
    assert sys.version_info[:2] >= (3, 12)
    assert [
        (x["rule_id"], len(x["evidence_ids"])) for x in sorted(a["alerts"], key=lambda a: a["rule_id"])
    ] == [("DET-001", 10), ("DET-003", 11), ("DET-006", 12)]


@pytest.mark.case("CI-003")
def test_coverage_policy():
    import importlib.util

    spec = importlib.util.spec_from_file_location("coverage_gate", ROOT / "tools" / "coverage_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.check({"totals": {"covered_branches": 84, "num_branches": 100}, "files": {}})
    assert not module.check({"totals": {"covered_branches": 85, "num_branches": 100}, "files": {}})
    assert module.check(
        {
            "totals": {"covered_branches": 99, "num_branches": 100},
            "files": {"src/lia/rules.py": {"summary": {"covered_branches": 89, "num_branches": 100}}},
        }
    )


@pytest.mark.case("CI-004")
@pytest.mark.delivery
def test_mutation_record():
    path = ROOT / "reports" / "mutations.json"
    if not path.exists():
        pytest.skip("Run tools/mutation_check.py before release acceptance.")
    result = json.loads(path.read_text())
    assert len(result["mutations"]) == 6 and all(m["killed"] for m in result["mutations"])


@pytest.mark.case("CI-005")
def test_label_independence(pipeline):
    events = story()
    a, _, _, _ = pipeline(events)
    for e in events:
        e["ground_truth"] = "benign"
    b, _, _, _ = pipeline(events)
    assert [(x["rule_id"], x["evidence_ids"]) for x in a["alerts"]] == [
        (x["rule_id"], x["evidence_ids"]) for x in b["alerts"]
    ]


@pytest.mark.case("CI-006")
def test_frozen_suite(tmp_path):
    suite = tmp_path / "suite.yml"
    write_json(suite, {"schema": "lia-suite/v1", "scenarios": []})
    write_json(tmp_path / "freeze.json", {"suite_sha256": sha_file(suite)})
    suite.write_text(suite.read_text() + "\n")
    with pytest.raises(LiaError, match="frozen_suite_changed"):
        replay(suite, tmp_path / "run")


@pytest.mark.case("CI-007")
def test_supply_chain_configuration():
    import re

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    refs = re.findall(r"uses:\s+[^@\s]+@([^\s]+)", workflow)
    assert refs and all(re.fullmatch("[a-f0-9]{40}", r) for r in refs)
    assert (ROOT / "uv.lock").is_file() and (ROOT / "requirements.lock.txt").is_file()
    report = ROOT / "reports" / "dependency-audit.json"
    if report.exists():
        data = json.loads(report.read_text())
        assert all(not d.get("vulns") for d in data.get("dependencies", []))


@pytest.mark.case("CI-008")
def test_quickstart(tmp_path):
    from typer.testing import CliRunner

    from lia.cli import app

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "uv sync --locked" in readme and "lia demo --output" in readme
    result = CliRunner().invoke(app, ["demo", "--output", str(tmp_path / "demo")])
    assert result.exit_code == 0


@pytest.mark.case("SEC-020")
@pytest.mark.delivery
def test_container():
    if not shutil.which("docker") or not os.environ.get("LIA_TEST_DOCKER"):
        pytest.skip(
            "Docker engine is unavailable; CI performs the real non-root, read-only, offline container run."
        )
    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/work:uid=10001,gid=10001",
            "--tmpfs",
            "/tmp",
            "lia:test",
            "demo",
            "--output",
            "/work/demo",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["alerts"] == 3


def test_benchmark_smoke(tmp_path):
    profile = tmp_path / "profile.yml"
    write_json(profile, {"events": 100, "runs": 1, "warmups": 0})
    result = run_benchmark(profile, tmp_path / "bench")
    assert len(result["runs"]) == 1 and result["runs"][0]["counts"]["rows_seen"] == 100
    assert result["input_bytes"] > 0 and result["median_seconds"] > 0
