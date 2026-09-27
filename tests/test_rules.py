import copy
import itertools

import pytest

from lia.common import LiaError
from lia.config import load_yaml
from lia.rules import duration, evaluate, validate_rule, validate_rules


@pytest.mark.case("DSL-001")
def test_valid(rules):
    assert len(validate_rules(rules)) == 8


@pytest.mark.case("DSL-002")
@pytest.mark.parametrize("key", ["description", "required_capabilities"])
def test_required(rules, key):
    rule = copy.deepcopy(rules[0])
    del rule[key]
    with pytest.raises(LiaError):
        validate_rule(rule)


@pytest.mark.case("DSL-003")
def test_unknown(rules):
    rule = copy.deepcopy(rules[0])
    rule["unsupported_modifier"] = True
    with pytest.raises(LiaError):
        validate_rule(rule)


@pytest.mark.case("DSL-004")
def test_duplicate(rules):
    with pytest.raises(LiaError, match="duplicate_rule_id"):
        validate_rules(rules + [rules[0]])


@pytest.mark.case("DSL-005")
def test_duplicate_yaml(tmp_path):
    p = tmp_path / "r.yml"
    p.write_text("threshold: 10\nthreshold: 11\n")
    with pytest.raises(LiaError, match="duplicate"):
        load_yaml(p)


@pytest.mark.case("DSL-006", "DSL-018")
@pytest.mark.parametrize("schema", ["lia-rule/v99", "sigma"])
def test_schema(rules, schema):
    r = copy.deepcopy(rules[0])
    r["schema"] = schema
    with pytest.raises(LiaError, match="unsupported_rule_format"):
        validate_rule(r)


@pytest.mark.case("DSL-007")
@pytest.mark.parametrize("value", ["0m", "-1m", "5", None, "25h"])
def test_windows(value):
    with pytest.raises(LiaError):
        duration(value)


@pytest.mark.case("DSL-008")
@pytest.mark.parametrize("threshold", [{"gte": -1}, {"gte": 1.5}, {"gt": 10}, {"gte": True}])
def test_thresholds(rules, threshold):
    r = copy.deepcopy(rules[0])
    r["aggregate"]["threshold"] = threshold
    with pytest.raises(LiaError):
        validate_rule(r)


@pytest.mark.case("DSL-009", "DSL-010")
def test_unknown_logic(event):
    e = event(user=None)
    expression = {"field": "actor.user_id", "equals": "alice"}
    assert evaluate(expression, e) is None
    assert evaluate({"not": expression}, e) is None


@pytest.mark.case("DSL-011")
@pytest.mark.parametrize("user,expected", [(None, False), ("", False), ("alice", True)])
def test_exists(event, user, expected):
    assert evaluate({"field": "actor.user_id", "exists": True}, event(user=user)) is expected


@pytest.mark.case("DSL-012")
def test_truth_table(event):
    e = event(user=None)
    expressions = {
        True: {"field": "event.outcome", "equals": "failure"},
        False: {"field": "event.outcome", "equals": "success"},
        None: {"field": "actor.user_id", "equals": "x"},
    }
    for a, b in itertools.product([True, False, None], repeat=2):
        expected_all = False if a is False or b is False else None if a is None or b is None else True
        expected_any = True if a is True or b is True else None if a is None or b is None else False
        assert evaluate({"all": [expressions[a], expressions[b]]}, e) is expected_all
        assert evaluate({"any": [expressions[a], expressions[b]]}, e) is expected_any


@pytest.mark.case("DSL-013")
@pytest.mark.parametrize(
    "address,expected", [("192.0.2.0", True), ("192.0.2.255", True), ("198.51.100.1", False)]
)
def test_cidr(event, address, expected):
    assert (
        evaluate({"field": "network.client_ip", "cidr_match": "192.0.2.0/24"}, event(address=address))
        is expected
    )


@pytest.mark.case("DSL-014")
def test_distinct(event, detect_events):
    repeated = [event(i, i) for i in range(20)]
    unique = [event(i, i, user=f"u{i}") for i in range(10)]
    assert not any(a["rule_id"] == "DET-002" for a in detect_events(repeated)[0])
    assert next(a for a in detect_events(unique)[0] if a["rule_id"] == "DET-002")["metrics"]["distinct"] == 10


@pytest.mark.case("DSL-015")
def test_cycle(rules):
    selected = [copy.deepcopy(r) for r in rules if r["id"] in ["DET-003", "DET-006"]]
    selected[0]["aggregate"]["upstream"] = "DET-006"
    with pytest.raises(LiaError, match="dependency_cycle"):
        validate_rules(selected)


@pytest.mark.case("DSL-016")
def test_missing_dependency(rules):
    r = copy.deepcopy(next(r for r in rules if r["id"] == "DET-003"))
    r["aggregate"]["upstream"] = "DET-999"
    with pytest.raises(LiaError, match="missing_dependency"):
        validate_rules([r])


@pytest.mark.case("DSL-017")
def test_tenant_required(rules):
    r = copy.deepcopy(rules[0])
    r["aggregate"]["group_by"].remove("tenant.id")
    with pytest.raises(LiaError, match="namespace_required"):
        validate_rule(r)


@pytest.mark.case("DSL-019")
def test_attack_id(rules):
    r = copy.deepcopy(rules[0])
    r["attack"][0]["technique_id"] = "T9999"
    with pytest.raises(LiaError, match="unknown_technique"):
        validate_rule(r)
    r["attack"][0]["technique_id"] = "T1086"
    validate_rule(r)


@pytest.mark.case("DSL-020")
def test_rule_version(rules):
    from lia.common import digest

    r = copy.deepcopy(rules[0])
    old = digest(r)
    r["version"] += 1
    r["aggregate"]["threshold"]["gte"] = 11
    validate_rule(r)
    assert digest(r) != old
