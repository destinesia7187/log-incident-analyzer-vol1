"""Negative contracts for bounded configuration and rule evaluation."""

import copy

import pytest

from lia.common import LiaError, json_load
from lia.config import Config, Heartbeat, load_yaml, parse_model
from lia.demo import raw_event, story, write_input
from lia.detection import detect
from lia.evaluation import metrics, replay, wilson
from lia.normalize import normalize, parse_time
from lia.pipeline import analyze, read_run, update_case
from lia.rules import evaluate, validate_expr, validate_rule, validate_rules


@pytest.mark.parametrize("text", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":Infinity}'])
def test_strict_json(text):
    with pytest.raises(LiaError):
        json_load(text)


@pytest.mark.parametrize("value", [None, 123, "2026-01-01", "nonsense", "2026-13-01T00:00:00Z"])
def test_invalid_time(value):
    with pytest.raises(LiaError):
        parse_time(value)


def test_bad_timezone():
    with pytest.raises(LiaError):
        parse_time("2026-01-01T00:00:00", "Invalid/Zone")


@pytest.mark.parametrize(
    "expression",
    [
        [],
        {"all": []},
        {"any": []},
        {"all": [{"field": "event.action", "equals": "x"}], "extra": 1},
        {"field": "missing", "equals": "x"},
        {"field": "actor.user_id", "regex": ".*"},
        {"field": "actor.user_id", "in": []},
        {"field": "actor.user_id", "in": "bad"},
        {"field": "actor.user_id", "exists": "yes"},
        {"field": "actor.user_id", "starts_with": 1},
        {"field": "network.client_ip", "cidr_match": "bad"},
    ],
)
def test_invalid_expressions(expression):
    with pytest.raises(LiaError):
        validate_expr(expression)


def test_expression_limits():
    expression = {"field": "event.action", "equals": "x"}
    for _ in range(9):
        expression = {"not": expression}
    with pytest.raises(LiaError):
        validate_expr(expression)
    with pytest.raises(LiaError):
        validate_expr({"all": [{"field": "event.action", "equals": "x"}] * 1001})


def test_predicate_types(event):
    e = event(user="alice", http={"status": 200})
    assert evaluate({"field": "actor.user_id", "in": ["bob", "alice"]}, e)
    assert evaluate({"field": "http.status", "in": ["200"]}, e) is False
    assert evaluate({"field": "actor.user_id", "starts_with": "ali"}, e)
    assert evaluate({"field": "http.status", "starts_with": "2"}, e) is False
    assert evaluate({"field": "actor.user_id", "cidr_match": "192.0.2.0/24"}, e) is False
    with pytest.raises(LiaError):
        evaluate({"field": "actor.user_id", "unknown": True}, e)


@pytest.mark.parametrize(
    "change",
    [
        {"id": "invalid"},
        {"version": 0},
        {"version": True},
        {"severity": "critical"},
        {"title": ""},
        {"references": []},
        {"required_fields": ["bad"]},
        {"attack": "bad"},
        {"attack": [{"technique_id": "T1110", "mapping_status": "certain"}]},
    ],
)
def test_invalid_rule_metadata(rules, change):
    r = copy.deepcopy(rules[0])
    r.update(change)
    with pytest.raises(LiaError):
        validate_rule(r)


@pytest.mark.parametrize(
    "aggregate",
    [
        {
            "type": "event_count",
            "group_by": ["tenant.id", "app.id", "bad"],
            "window": "5m",
            "threshold": {"gte": 10},
        },
        {
            "type": "distinct_count",
            "group_by": ["tenant.id", "app.id"],
            "window": "5m",
            "threshold": {"gte": 10},
            "field": "bad",
        },
        {"type": "multi_count", "group_by": ["tenant.id", "app.id"], "window": "5m", "measures": []},
        {
            "type": "multi_count",
            "group_by": ["tenant.id", "app.id"],
            "window": "5m",
            "measures": [{"name": "x", "field": "bad", "threshold": {"gte": 10}}],
        },
        {"type": "sequence", "group_by": ["tenant.id", "app.id"], "strict_order": False},
        {
            "type": "sequence",
            "group_by": ["tenant.id", "app.id"],
            "strict_order": True,
            "selection": "latest_qualifying_window",
            "match_fields": ["actor.user_id"],
        },
        {"type": "unknown", "group_by": ["tenant.id", "app.id"]},
        {
            "type": "event_count",
            "group_by": ["tenant.id", "app.id"],
            "window": "5m",
            "threshold": {"gte": 10},
            "extra": 1,
        },
    ],
)
def test_invalid_aggregate(rules, aggregate):
    r = copy.deepcopy(rules[0])
    r["aggregate"] = aggregate
    with pytest.raises(LiaError):
        validate_rule(r)


def test_rules_limits(rules):
    with pytest.raises(LiaError):
        validate_rules([])
    with pytest.raises(LiaError):
        validate_rules([rules[0]] * 101)


def test_bad_config_limits(tmp_path):
    with pytest.raises(ValueError):
        Heartbeat(coverage_start="x", coverage_end="y", expected_interval_s=60, max_gap_s=20)
    with pytest.raises(LiaError):
        parse_model(Config, {"trusted_proxy_cidrs": ["invalid"]})
    p = tmp_path / "config.yml"
    p.write_text("x: " + "a" * (2 * 1024**2))
    with pytest.raises(LiaError, match="size"):
        load_yaml(p)
    p.write_text("x: " + "[" * 17 + "1" + "]" * 17)
    with pytest.raises(LiaError, match="depth"):
        load_yaml(p)


def test_normalization_edge_cases(source):
    with pytest.raises(LiaError):
        normalize([], source, Config(), b"k")
    with pytest.raises(LiaError):
        normalize({}, source, Config(), b"k")
    e = normalize(raw_event(0, actor=[], auth=[], http={"path": "http://[bad"}), source, Config(), b"k")
    assert "invalid:actor" in e.flags and "invalid:http.path" in e.flags
    folded = normalize(
        raw_event(0, user="Alice"),
        source.model_copy(update={"casefold_user": True, "rounding": "unknown"}),
        Config(),
        b"k",
    )
    assert folded.get("actor.user_id") == "alice" and "unknown_time_rounding" in folded.flags
    config = Config(trusted_proxy_cidrs=["10.0.0.0/8"])
    src = source.model_copy(update={"forwarded_enabled": True})
    e = normalize(
        raw_event(0, network={"peer_ip": "10.0.0.1", "forwarded_for": "x" * 4097}), src, config, b"k"
    )
    assert e.get("network.client_ip") == "10.0.0.1"
    e = normalize(
        raw_event(0, network={"peer_ip": "10.0.0.1", "forwarded_for": "10.0.0.2"}), src, config, b"k"
    )
    assert "no_untrusted_forwarded_hop" in e.flags


def test_pipeline_guards(tmp_path, pipeline):
    manifest = write_input(tmp_path / "input", story())
    with pytest.raises(LiaError, match="unknown_enabled_rule"):
        analyze(manifest, tmp_path / "out", Config(enabled_rules=["DET-999"]))
    with pytest.raises(LiaError, match="unsupported_output_format"):
        analyze(manifest, tmp_path / "out", formats=["csv"])
    a, r, _ = analyze(manifest, tmp_path / "out", Config(enabled_rules=["DET-001"]))
    assert {x["rule_id"] for x in a["alerts"]} == {"DET-001"}
    with pytest.raises(LiaError):
        read_run(tmp_path / "missing")
    cid = a["cases"][0]["id"]
    with pytest.raises(LiaError):
        update_case(tmp_path / "out", cid, "")
    with pytest.raises(LiaError):
        update_case(tmp_path / "out", cid, "u", status="closed", verdict="benign_activity", reason="x")
    with pytest.raises(LiaError):
        update_case(tmp_path / "out", cid, "u", note="")


def test_detection_expiry_and_sort(event, source, rules, detect_events):
    values = [event(i, i) for i in range(10)] + [event(11, 10000, user="other")]
    result = detect_events(values)
    assert result[0]
    with pytest.raises(LiaError, match="events_not_sorted"):
        detect(reversed(values), rules, Config(), [source])
    hb = source.model_copy(
        update={
            "heartbeat": Heartbeat(
                coverage_start="2026-01-01T00:00:00Z",
                coverage_end="2026-01-01T00:03:00Z",
                expected_interval_s=60,
                max_gap_s=180,
            )
        }
    )
    assert not detect([], rules, Config(), [hb])[2]


def test_sequence_merge(event, detect_events):
    values = [event(i, i) for i in range(10)] + [event(10 + i, 20 + i, outcome="success") for i in range(50)]
    alerts = detect_events(values)[0]
    seq = [a for a in alerts if a["rule_id"] == "DET-003"]
    assert len(seq) == 1 and len(seq[0]["evidence_ids"]) == 60


def test_previous_window_snapshot(event, detect_events):
    values = [event(i, i) for i in range(10)] + [event(10, 400), event(11, 401, outcome="success")]
    seq = [a for a in detect_events(values)[0] if a["rule_id"] == "DET-003"]
    assert (
        len(seq) == 1 and values[-2].uid not in seq[0]["evidence_ids"] and len(seq[0]["evidence_ids"]) == 11
    )


def test_uncertainty_of_earlier_evidence(event, source, detect_events):
    values = [
        event(
            i, i, source_override=source.model_copy(update={"clock_uncertainty_ms": 20000 if i == 0 else 0})
        )
        for i in range(10)
    ]
    values.append(event(20, 10, outcome="success"))
    assert not any(a["rule_id"] == "DET-003" for a in detect_events(values)[0])


def test_statistics_empty_and_benign():
    assert wilson(0, 0) is None
    lo, hi = wilson(5, 10)
    assert 0 < lo < 0.5 < hi < 1
    m = metrics([], [])
    assert m["precision"] is None and m["eligible_recall"] is None


def test_replay_guards(tmp_path):
    from lia.common import write_json

    p = tmp_path / "suite.yml"
    write_json(p, {"schema": "bad"})
    with pytest.raises(LiaError):
        replay(p, tmp_path / "out")
    write_json(p, {"schema": "lia-suite/v1", "scenarios": []})
    write_json(tmp_path / "freeze.json", {"suite_sha256": "bad"})
    with pytest.raises(LiaError, match="frozen_suite_changed"):
        replay(p, tmp_path / "out")


def test_context_scope_and_relations():
    from test_triage_quality import ctx, fake_alert

    from lia.triage import applies, assemble

    entry = ctx("approved")
    for field, value in [
        ("tenant_id", "other"),
        ("application_id", "other"),
        ("user_id", "other"),
        ("rule_id", "DET-003"),
    ]:
        a = fake_alert(1)
        a[field] = value
        assert not applies(entry, a)
    address_entry = ctx("nat", client_ip="192.0.2.2")
    assert not applies(address_entry, fake_alert(1))
    a, b = fake_alert(1), fake_alert(2, rule="DET-002", user=None)
    b["evidence_ids"] = a["evidence_ids"][:]
    cases = assemble([a, b], Config())
    assert len(cases) == 2 and cases[0]["related"] == [cases[1]["id"]]
    assert cases[1]["related"] == [cases[0]["id"]]
