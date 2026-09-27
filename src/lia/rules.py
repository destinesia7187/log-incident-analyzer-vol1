"""A bounded declarative rule language with three-valued predicates."""

from __future__ import annotations

import ipaddress
import re
from importlib.resources import files
from pathlib import Path
from typing import Any

from .common import LiaError
from .config import load_yaml
from .normalize import Event

FIELDS = {
    "tenant.id",
    "app.id",
    "actor.user_id",
    "actor.role",
    "target.user_id",
    "target.resource_id",
    "network.client_ip",
    "network.peer_ip",
    "event.action",
    "event.outcome",
    "http.path",
    "http.status",
    "http.method",
    "http.request_id",
    "auth.session_ref",
    "auth.mfa_request_id",
    "auth.device_ref",
    "auth.factor_kind",
}
TECHNIQUES = {"T1110", "T1110.001", "T1110.003", "T1621", "T1098.005"}
DEPRECATED = {"T1086"}
META = {
    "schema",
    "id",
    "version",
    "title",
    "status",
    "description",
    "rationale",
    "owner",
    "references",
    "tests",
    "required_capabilities",
    "required_fields",
    "select",
    "aggregate",
    "severity",
    "attack",
    "false_positives",
    "next_steps",
}


def duration(value: Any) -> int:
    if not isinstance(value, str) or not (m := re.fullmatch(r"([1-9]\d*)(s|m|h)", value)):
        raise LiaError("invalid_window")
    result = int(m[1]) * {"s": 1, "m": 60, "h": 3600}[m[2]] * 1000000
    if result > 24 * 3600 * 1000000:
        raise LiaError("window_limit")
    return result


def validate_expr(node: Any, level: int = 0, count: list[int] | None = None) -> None:
    count = count if count is not None else [0]
    count[0] += 1
    if level > 8 or count[0] > 1000 or not isinstance(node, dict):
        raise LiaError("expression_limit")
    for op in ("all", "any", "not"):
        if op in node:
            if set(node) != {op}:
                raise LiaError("invalid_expression")
            children = node[op] if op != "not" else [node[op]]
            if not isinstance(children, list) or not children:
                raise LiaError("empty_expression")
            for child in children:
                validate_expr(child, level + 1, count)
            return
    if node.get("field") not in FIELDS:
        raise LiaError("unknown_field")
    operators = set(node) - {"field"}
    if len(operators) != 1 or not operators <= {"equals", "in", "exists", "cidr_match", "starts_with"}:
        raise LiaError("unsupported_operator")
    op = next(iter(operators))
    value = node[op]
    if op == "in" and (not isinstance(value, list) or not value):
        raise LiaError("invalid_in")
    if op == "exists" and type(value) is not bool:
        raise LiaError("invalid_exists")
    if op == "starts_with" and not isinstance(value, str):
        raise LiaError("invalid_prefix")
    if op == "cidr_match":
        try:
            ipaddress.ip_network(value)
        except (ValueError, TypeError) as exc:
            raise LiaError("invalid_cidr") from exc


def evaluate(node: dict, event: Event) -> bool | None:
    if "not" in node:
        value = evaluate(node["not"], event)
        return None if value is None else not value
    for op in ("all", "any"):
        if op in node:
            values = [evaluate(child, event) for child in node[op]]
            if op == "all":
                return False if False in values else None if None in values else True
            return True if True in values else None if None in values else False
    value = event.get(node["field"])
    if "exists" in node:
        return (value is not None and value != "") == node["exists"]
    if value is None:
        return None
    if "equals" in node:
        return type(value) is type(node["equals"]) and value == node["equals"]
    if "in" in node:
        return any(type(value) is type(v) and value == v for v in node["in"])
    if "starts_with" in node:
        return isinstance(value, str) and value.startswith(node["starts_with"])
    if "cidr_match" in node:
        try:
            return ipaddress.ip_address(value) in ipaddress.ip_network(node["cidr_match"])
        except ValueError:
            return False
    raise LiaError("unsupported_operator")


def threshold(value: Any) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != {"gte"}
        or type(value["gte"]) is not int
        or value["gte"] <= 0
    ):
        raise LiaError("invalid_threshold")


def validate_rule(rule: dict) -> None:
    if not isinstance(rule, dict) or rule.get("schema") != "lia-rule/v1":
        raise LiaError("unsupported_rule_format")
    if set(rule) != META:
        raise LiaError("rule_fields")
    if not re.fullmatch(r"DET-\d{3}", str(rule["id"])):
        raise LiaError("invalid_rule_id")
    if type(rule["version"]) is not int or rule["version"] <= 0:
        raise LiaError("invalid_rule_version")
    if rule["severity"] not in {"low", "medium", "high"}:
        raise LiaError("invalid_severity")
    for name in ("title", "description", "rationale", "owner", "status"):
        if not isinstance(rule[name], str) or not rule[name].strip():
            raise LiaError("invalid_metadata")
    for name in (
        "references",
        "tests",
        "required_capabilities",
        "required_fields",
        "false_positives",
        "next_steps",
    ):
        if (
            not isinstance(rule[name], list)
            or not rule[name]
            or not all(isinstance(v, str) for v in rule[name])
        ):
            raise LiaError("invalid_metadata")
    if not set(rule["required_fields"]) <= FIELDS:
        raise LiaError("unknown_field")
    validate_expr(rule["select"])
    a = rule["aggregate"]
    if not isinstance(a, dict) or not {"tenant.id", "app.id"} <= set(a.get("group_by", [])):
        raise LiaError("namespace_required")
    if not set(a["group_by"]) <= FIELDS:
        raise LiaError("unknown_field")
    typ = a.get("type")
    allowed = {"type", "group_by", "window"}
    if typ == "event_count":
        allowed |= {"threshold"}
        threshold(a.get("threshold"))
    elif typ == "distinct_count":
        allowed |= {"threshold", "field"}
        threshold(a.get("threshold"))
        if a.get("field") not in FIELDS:
            raise LiaError("unknown_field")
    elif typ == "multi_count":
        allowed |= {"measures"}
        if not isinstance(a.get("measures"), list) or not a["measures"]:
            raise LiaError("invalid_measures")
        for m in a["measures"]:
            if set(m) != {"name", "field", "threshold"} or m["field"] not in FIELDS | {None}:
                raise LiaError("invalid_measures")
            threshold(m["threshold"])
    elif typ == "sequence":
        allowed = {"type", "group_by", "upstream", "match_fields", "max_gap", "strict_order", "selection"}
        if a.get("strict_order") is not True or a.get("selection") != "latest_qualifying_window":
            raise LiaError("invalid_sequence")
        if (
            not {"tenant.id", "app.id"} <= set(a.get("match_fields", []))
            or not set(a["match_fields"]) <= FIELDS
        ):
            raise LiaError("namespace_required")
        duration(a.get("max_gap"))
    else:
        raise LiaError("unsupported_aggregate")
    if set(a) != allowed:
        raise LiaError("aggregate_fields")
    if typ != "sequence":
        duration(a.get("window"))
    if not isinstance(rule["attack"], list):
        raise LiaError("invalid_mapping")
    for mapping in rule["attack"]:
        if (
            set(mapping) != {"technique_id", "mapping_status"}
            or mapping["technique_id"] not in TECHNIQUES | DEPRECATED
        ):
            raise LiaError("unknown_technique")
        if mapping["mapping_status"] not in {"candidate", "supported_behavior"}:
            raise LiaError("invalid_mapping_status")


def validate_rules(rules: list[dict]) -> list[dict]:
    if not rules or len(rules) > 100:
        raise LiaError("rules_count")
    for rule in rules:
        validate_rule(rule)
    indexed = {r["id"]: r for r in rules}
    if len(indexed) != len(rules):
        raise LiaError("duplicate_rule_id")
    visiting: set[str] = set()
    visited: set[str] = set()
    result: list[dict] = []

    def visit(rid: str) -> None:
        if rid in visiting:
            raise LiaError("dependency_cycle")
        if rid not in indexed:
            raise LiaError("missing_dependency")
        if rid in visited:
            return
        visiting.add(rid)
        rule = indexed[rid]
        if rule["aggregate"]["type"] == "sequence":
            visit(rule["aggregate"]["upstream"])
        visiting.remove(rid)
        visited.add(rid)
        result.append(rule)

    for rid in sorted(indexed):
        visit(rid)
    return result


def load_rules(path: Path | None = None) -> list[dict]:
    root = path or Path(str(files("lia").joinpath("resources/rules")))
    paths = sorted(root.glob("*.yml")) if root.is_dir() else [root]
    return validate_rules([load_yaml(p) for p in paths])
