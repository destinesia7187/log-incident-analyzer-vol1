from __future__ import annotations

import json
from pathlib import Path

import pytest

from lia.config import Config, Source
from lia.demo import raw_event, write_input
from lia.detection import detect
from lia.normalize import normalize
from lia.pipeline import analyze
from lia.rules import load_rules


@pytest.fixture
def source():
    return Source(
        path="app.jsonl",
        format="app-audit-v1",
        source_id="test-audit",
        tenant_id="t1",
        application_id="a1",
        authority="idp_audit",
        platform_scope="identity_provider",
        precision_us=1,
        declared_capabilities=[
            "auth.login.failure",
            "auth.login.success",
            "auth.mfa.challenge",
            "auth.mfa.enroll",
            "authz.denied",
            "http.request",
        ],
    )


@pytest.fixture
def rules():
    return load_rules()


@pytest.fixture
def event(source):
    def make(index=0, seconds=0, source_override=None, config=None, **kwargs):
        return normalize(
            raw_event(index, seconds, **kwargs),
            source_override or source,
            config or Config(),
            b"k" * 32,
            artifact="test",
            line=index + 1,
            record_digest=str(index),
        )

    return make


@pytest.fixture
def detect_events(rules, source):
    def run(events, config=None, custom_rules=None):
        return detect(
            sorted(events, key=lambda e: (e.time, e.uid)), custom_rules or rules, config or Config(), [source]
        )

    return run


@pytest.fixture
def pipeline(tmp_path):
    counter = [0]

    def run(events, config=None, rules=None, **kwargs):
        counter[0] += 1
        manifest = write_input(tmp_path / f"input-{counter[0]}", events)
        output = tmp_path / "runs" / f"run-{counter[0]}"
        analysis, metadata, code = analyze(manifest, output, config, rules, **kwargs)
        return analysis, metadata, code, output

    return run


def pytest_collection_modifyitems(items):
    for item in items:
        for marker in item.iter_markers("case"):
            for case_id in marker.args:
                item.user_properties.append(("spec_case", case_id))


OUTCOMES = []


def pytest_runtest_logreport(report):
    if report.when == "call" or report.skipped:
        OUTCOMES.append(
            {
                "nodeid": report.nodeid,
                "outcome": report.outcome,
                "case_ids": sorted({value for key, value in report.user_properties if key == "spec_case"}),
            }
        )


def pytest_sessionfinish(session, exitstatus):
    directory = Path("reports")
    directory.mkdir(exist_ok=True)
    (directory / "test-outcomes.json").write_text(json.dumps(OUTCOMES, indent=2), encoding="utf-8")
