"""Transparent case assembly and priority policy."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from .common import digest
from .config import Config, ContextEntry
from .normalize import parse_time

BASE = {"low": 20, "medium": 40, "high": 60}


def applies(entry: ContextEntry, alert: dict) -> bool:
    if entry.tenant_id != alert["tenant_id"] or entry.application_id != alert["application_id"]:
        return False
    if entry.user_id and entry.user_id != alert["user_id"]:
        return False
    if entry.client_ip and entry.client_ip != alert["client_ip"]:
        return False
    if entry.rule_id and entry.rule_id != alert["rule_id"]:
        return False
    return (
        parse_time(entry.valid_from)[0] <= alert["start"] and alert["end"] < parse_time(entry.expires_at)[0]
    )


def assemble(alerts: list[dict], config: Config) -> list[dict]:
    groups: dict[tuple, list[list[dict]]] = defaultdict(list)
    alert_group: dict[str, list[dict]] = {}
    for alert in sorted(alerts, key=lambda a: (a["start"], a["id"])):
        contexts = [c for c in config.context if applies(c, alert)]
        alert["context_ids"] = [c.id for c in contexts]
        suppression = [c.id for c in contexts if c.kind == "suppression"]
        alert["suppressed"] = bool(suppression)
        alert["suppression_ids"] = suppression
        if any(c.kind == "nat" for c in contexts):
            alert["alternatives"] = list(
                dict.fromkeys(alert["alternatives"] + ["This source is a declared shared NAT."])
            )
        scope = (alert["tenant_id"], alert["application_id"])
        identity = (
            ("user", alert["user_id"])
            if alert["user_id"]
            else ("source", alert["rule_id"], alert["client_ip"])
        )
        key = scope + identity
        target = None
        for parent_id in alert["upstream_alert_ids"]:
            candidate = alert_group.get(parent_id)
            if candidate and alert["end"] - min(a["start"] for a in candidate) <= 3600000000:
                target = candidate
                break
        if target is None and groups[key]:
            last = groups[key][-1]
            if (
                alert["start"] - max(a["end"] for a in last) <= 900000000
                and alert["end"] - min(a["start"] for a in last) <= 3600000000
            ):
                target = last
        if target is None:
            target = []
            groups[key].append(target)
        target.append(alert)
        alert_group[alert["id"]] = target
    unique_groups = {id(g): g for g in alert_group.values()}
    cases = []
    for group in unique_groups.values():
        ids = sorted(a["id"] for a in group)
        base = max(BASE[a["severity"]] for a in group)
        context_ids = {cid for a in group for cid in a["context_ids"]}
        contexts = [c for c in config.context if c.id in context_ids]
        components: list[dict[str, Any]] = [{"reason": "maximum_rule_severity", "value": base}]
        if any(c.kind == "critical" for c in contexts):
            components.append({"reason": "critical_asset", "value": 15})
        chain = any(a["rule_id"] == "DET-006" for a in group)
        if chain:
            components.append({"reason": "mfa_registration_sequence", "value": 15})
        if any(c.kind == "approved" for c in contexts):
            components.append({"reason": "approved_activity", "value": -20})
        score = max(0, min(100, sum(c["value"] for c in components)))
        priority = (
            "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
        )
        evidence = sorted({uid for a in group for uid in a["evidence_ids"]})
        strongest = max(group, key=lambda a: (BASE[a["severity"]], a["rule_id"]))
        edges = []
        for a in group:
            for parent in a["upstream_alert_ids"]:
                if parent in ids:
                    pa = next(x for x in group if x["id"] == parent)
                    edges.append(
                        {
                            "from": parent,
                            "to": a["id"],
                            "reason": "explicit_sequence",
                            "evidence_ids": sorted(set(pa["evidence_ids"]) & set(a["evidence_ids"])),
                        }
                    )
        parents = {aid: aid for aid in ids}

        def root(aid):
            while parents[aid] != aid:
                aid = parents[aid]
            return aid

        for edge in edges:
            parents[root(edge["to"])] = root(edge["from"])
        for before, after in zip(group, group[1:]):
            if root(before["id"]) != root(after["id"]):
                edges.append(
                    {
                        "from": before["id"],
                        "to": after["id"],
                        "reason": "same_identity_time_window",
                        "evidence_ids": sorted(set(before["evidence_ids"]) | set(after["evidence_ids"])),
                    }
                )
                parents[root(after["id"])] = root(before["id"])
        cases.append(
            {
                "id": "CASE-" + digest(ids)[:24],
                "title": strongest["title"],
                "tenant_id": strongest["tenant_id"],
                "application_id": strongest["application_id"],
                "user_id": strongest["user_id"],
                "client_ip": strongest["client_ip"],
                "start": min(a["start"] for a in group),
                "end": max(a["end"] for a in group),
                "alert_ids": ids,
                "evidence_ids": evidence,
                "status": "new",
                "notes": [],
                "history": [],
                "severity": strongest["severity"],
                "priority": priority,
                "score": score,
                "score_components": components,
                "decision": "escalate" if priority in ("high", "critical") or chain else "review",
                "confidence": "limited" if any(a["confidence"] == "limited" for a in group) else "supported",
                "confidence_reasons": ["Source flags or unverified authority."]
                if any(a["confidence"] == "limited" for a in group)
                else ["Required evidence fields and ordering are available."],
                "facts": [
                    {
                        "text": a["title"] + ": documented rule conditions matched.",
                        "rule_id": a["rule_id"],
                        "evidence_ids": a["evidence_ids"],
                    }
                    for a in group
                ],
                "hypotheses": ["Potential unauthorized activity; verify with the account or service owner."],
                "alternatives": sorted({v for a in group for v in a["alternatives"]}),
                "limitations": sorted({v for a in group for v in a["limitations"]}),
                "next_steps": sorted({v for a in group for v in a["next_steps"]}),
                "attack": list({m["technique_id"]: m for a in group for m in a["attack"]}.values()),
                "edges": edges,
                "related": [],
                "related_reasons": [],
                "context_ids": sorted(context_ids),
                "context_details": [c.model_dump(mode="json") for c in contexts],
                "suppressed": all(a["suppressed"] for a in group),
                "queue_visible": chain or not all(a["suppressed"] for a in group),
            }
        )
    # Relations are informational, never proof that actors behind an IP are identical.
    by_evidence: dict[str, list[dict]] = defaultdict(list)
    for case in cases:
        for uid in case["evidence_ids"]:
            for other in by_evidence[uid]:
                if (
                    other["tenant_id"] == case["tenant_id"]
                    and other["application_id"] == case["application_id"]
                ):
                    if other["id"] not in case["related"]:
                        case["related"].append(other["id"])
                        other["related"].append(case["id"])
                        case["related_reasons"].append({"case_id": other["id"], "reason": "shared_evidence"})
                        other["related_reasons"].append({"case_id": case["id"], "reason": "shared_evidence"})
            by_evidence[uid].append(case)
    previous_by_identity: dict[tuple, dict] = {}
    for case in sorted(cases, key=lambda c: (c["start"], c["id"])):
        key = (case["tenant_id"], case["application_id"], case["user_id"])
        prior = previous_by_identity.get(key)
        if (
            case["user_id"]
            and prior
            and case["start"] - prior["end"] <= 900000000
            and prior["id"] not in case["related"]
        ):
            case["related"].append(prior["id"])
            prior["related"].append(case["id"])
            case["related_reasons"].append({"case_id": prior["id"], "reason": "case_duration_limit"})
            prior["related_reasons"].append({"case_id": case["id"], "reason": "case_duration_limit"})
        previous_by_identity[key] = case
    return sorted(cases, key=lambda c: (-c["score"], c["start"], c["id"]))
