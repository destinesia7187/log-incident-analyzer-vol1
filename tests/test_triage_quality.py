import pytest

from lia.common import LiaError
from lia.config import Config, ContextEntry, Heartbeat
from lia.demo import story
from lia.detection import detect
from lia.normalize import parse_time
from lia.pipeline import read_run, update_case
from lia.triage import applies, assemble


def fake_alert(
    index, rule="DET-001", user="u", ip="192.0.2.1", start=0, end=10, tenant="t1", app="a1", severity="medium"
):
    return {
        "id": f"A{index}",
        "rule_id": rule,
        "rule_version": 1,
        "title": rule,
        "severity": severity,
        "tenant_id": tenant,
        "application_id": app,
        "user_id": user,
        "client_ip": ip,
        "start": start,
        "end": end,
        "evidence_ids": [f"e{index}"],
        "upstream_alert_ids": [],
        "attack": [],
        "alternatives": [],
        "next_steps": [],
        "limitations": [],
        "confidence": "supported",
        "suppressed": False,
        "context_ids": [],
    }


def ctx(kind="critical", **changes):
    return ContextEntry(
        **{
            "id": "context1",
            "kind": kind,
            "tenant_id": "t1",
            "application_id": "a1",
            "user_id": "u",
            "rule_id": "DET-001" if kind in ("approved", "suppression") else None,
            "source": "ticket",
            "author": "analyst",
            "reason": "test",
            "created_at": "1969-12-31T00:00:00Z",
            "valid_from": "1969-12-31T00:00:00Z",
            "expires_at": "1970-01-02T00:00:00Z",
            **changes,
        }
    )


@pytest.mark.case("TRI-001")
def test_chain(pipeline):
    analysis, _, _, _ = pipeline(story())
    assert len(analysis["cases"]) == 1 and len(analysis["cases"][0]["edges"]) == 2
    assert all(
        e["reason"] == "explicit_sequence" and e["evidence_ids"] for e in analysis["cases"][0]["edges"]
    )


@pytest.mark.case("TRI-002", "TRI-003", "TRI-004")
@pytest.mark.parametrize("field,value", [("user_id", "v"), ("tenant_id", "t2"), ("application_id", "a2")])
def test_separation(field, value):
    a, b = fake_alert(1), fake_alert(2)
    b[field] = value
    assert len(assemble([a, b], Config())) == 2


@pytest.mark.case("TRI-005")
def test_gap():
    assert len(assemble([fake_alert(1), fake_alert(2, start=900000011, end=900000012)], Config())) == 2


@pytest.mark.case("TRI-006")
def test_duration_split():
    alerts = [fake_alert(i, start=i * 600000000, end=i * 600000000 + 1) for i in range(8)]
    result = assemble(alerts, Config())
    assert len(result) == 2 and all(c["end"] - c["start"] <= 3600000000 for c in result)


@pytest.mark.case("TRI-007")
def test_base_score():
    cases = assemble([fake_alert(i, severity=s) for i, s in enumerate(["low", "medium", "high"])], Config())
    assert cases[0]["score"] == 60


@pytest.mark.case("TRI-008", "TRI-009", "TRI-010", "TRI-011")
@pytest.mark.parametrize(
    "kind,rule,expected,priority",
    [
        ("critical", "DET-001", 75, "high"),
        ("critical", "DET-006", 90, "critical"),
        ("approved", "DET-001", 40, "medium"),
        ("nat", "DET-001", 60, "high"),
    ],
)
def test_scoring(kind, rule, expected, priority):
    result = assemble([fake_alert(1, rule=rule, severity="high")], Config(context=[ctx(kind)]))[0]
    assert result["score"] == expected and result["priority"] == priority
    assert sum(c["value"] for c in result["score_components"]) == expected


@pytest.mark.case("TRI-012")
def test_context_expiry():
    entry = ctx("approved")
    end = parse_time(entry.expires_at)[0]
    assert not applies(entry, fake_alert(1, start=end, end=end))


@pytest.mark.case("TRI-013", "TRI-014")
@pytest.mark.parametrize("rule,visible", [("DET-001", False), ("DET-006", True)])
def test_suppression(rule, visible):
    entry = ctx("suppression", rule_id=rule)
    a = fake_alert(1, rule=rule)
    case = assemble([a], Config(context=[entry]))[0]
    assert a["suppressed"] and a["evidence_ids"] == ["e1"]
    assert case["queue_visible"] is visible
    if visible:
        assert case["decision"] == "escalate"


@pytest.mark.case("TRI-015")
def test_review_transitions(pipeline):
    a, _, _, out = pipeline(story())
    cid = a["cases"][0]["id"]
    update_case(out, cid, "local", status="in_review")
    update_case(
        out, cid, "local", status="closed", reason="Owner verified recovery", verdict="benign_activity"
    )
    c = update_case(out, cid, "local", status="in_review", reason="New evidence")
    assert c["status"] == "in_review" and len(c["history"]) == 3
    assert read_run(out)["cases"][0]["status"] == "in_review"


@pytest.mark.case("TRI-016")
def test_close_reason(pipeline):
    a, _, _, out = pipeline(story())
    cid = a["cases"][0]["id"]
    update_case(out, cid, "local", status="in_review")
    with pytest.raises(LiaError, match="closure_reason_required"):
        update_case(out, cid, "local", status="closed", verdict="benign_activity")
    c = read_run(out)["cases"][0]
    assert c["status"] == "in_review" and len(c["history"]) == 1


def quality(result, rid="DET-001"):
    return next(q for q in result[1] if q["rule_id"] == rid)


@pytest.mark.case("GAP-001", "GAP-002", "GAP-003")
@pytest.mark.parametrize(
    "missing,status,eligible", [(0, "ready", 10), (2, "degraded", 8), (10, "unavailable", 0)]
)
def test_readiness(event, detect_events, missing, status, eligible):
    q = quality(detect_events([event(i, i, user=None if i < missing else "u") for i in range(10)]))
    assert q["status"] == status and q["eligible"] == eligible and q["excluded"] == missing
    assert q["eligible_percent"] == eligible * 10


@pytest.mark.case("GAP-004")
def test_no_data(detect_events):
    q = quality(detect_events([]))
    assert q["status"] == "no_data" and q["eligible_percent"] is None


@pytest.mark.case("GAP-005")
def test_no_source(event, rules, source):
    src = source.model_copy(update={"declared_capabilities": ["http.request"]})
    result = detect([event(action="http.request", outcome="unknown")], rules, Config(), [src])
    assert quality(result, "DET-005")["status"] == "unavailable"


@pytest.mark.case("GAP-006")
def test_undeclared(event, rules, source):
    src = source.model_copy(update={"declared_capabilities": []})
    result = detect(
        sorted([event(i, i) for i in range(10)], key=lambda e: (e.time, e.uid)), rules, Config(), [src]
    )
    assert quality(result)["status"] == "degraded" and result[0]


@pytest.mark.case("GAP-007")
def test_per_rule_fields(event, detect_events):
    values = [
        event(
            i,
            i,
            user=None,
            action="http.request",
            outcome="unknown",
            http={"path": p, "method": "GET", "status": 404},
        )
        for i, p in enumerate(["/.env", "/.git/config", "/admin", "/backup.zip", "/config"])
    ]
    result = detect_events(values)
    assert quality(result, "DET-007")["eligible"] == 5 and any(a["rule_id"] == "DET-007" for a in result[0])


@pytest.mark.case("GAP-008")
def test_outcome_not_guessed(event, detect_events):
    result = detect_events([event(i, i, outcome="unknown") for i in range(10)])
    assert not result[0]
    assert "outcomes" in quality(result)["recommendation"]


@pytest.mark.case("GAP-009")
def test_incomplete_session(pipeline):
    a, _, _, _ = pipeline(story("incomplete"))
    assert {x["rule_id"] for x in a["alerts"]} == {"DET-001", "DET-003"}
    q = next(q for q in a["quality"] if q["rule_id"] == "DET-006")
    assert q["status"] == "unavailable" and q["missing_fields"]["auth.session_ref"] == 1


@pytest.mark.case("GAP-010")
def test_no_heartbeat_contract(detect_events):
    assert not any(f["code"] == "heartbeat_gap" for f in detect_events([])[2])


@pytest.mark.case("GAP-011")
def test_heartbeat_contract(rules, source):
    src = source.model_copy(
        update={
            "heartbeat": Heartbeat(
                coverage_start="2026-01-01T00:00:00Z",
                coverage_end="2026-01-01T00:10:00Z",
                expected_interval_s=60,
                max_gap_s=180,
            )
        }
    )
    result = detect([], rules, Config(), [src])
    f = result[2][0]
    assert f["code"] == "heartbeat_gap" and f["end"] - f["start"] == 600000000


@pytest.mark.case("GAP-012")
def test_coverage_is_rule_readiness(event, detect_events):
    result = detect_events([event(i, i) for i in range(10)])
    assert len(result[1]) == 8 and sum(q["status"] == "ready" for q in result[1]) == 3
    assert all("attack_coverage_percent" not in q for q in result[1])
