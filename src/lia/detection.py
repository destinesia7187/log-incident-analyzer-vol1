"""Event-time detection with explicit evidence and bounded active groups."""

from __future__ import annotations

import heapq
from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field

from .common import LiaError, digest
from .config import Config, Source
from .normalize import Event, parse_time
from .rules import duration, evaluate

HOUR = 3600 * 1000000


@dataclass
class Window:
    events: deque[Event] = field(default_factory=deque)
    counts: dict[str, Counter] = field(default_factory=dict)
    alert: dict | None = None
    last_qualifying: int | None = None
    last_event: Event | None = None
    last_index: int = -1
    first_index: int = 0
    next_index: int = 0
    qualifying_ids: tuple[str, ...] | None = None
    qualifying_start: int = 0
    qualifying_upper: int = 0
    bounds: deque[tuple[str, int]] = field(default_factory=deque)


def eligible(event: Event, rule: dict) -> bool:
    return event.uncertainty <= 30000000 and all(
        event.get(f) is not None and event.get(f) != "" for f in rule["required_fields"]
    )


def ordered(before: Event, after: Event) -> bool:
    return (
        "unknown_time_rounding" not in before.flags + after.flags and before.interval[1] < after.interval[0]
    )


def new_alert(
    rule: dict, group_key: tuple, events: list[Event], config: Config, upstream: list[str] | None = None
) -> dict:
    last = events[-1]
    first = min(events, key=lambda e: (e.time, e.uid))
    mappings = [
        dict(a)
        for a in rule["attack"]
        if a["technique_id"] != "T1098.005" or last.get("source.platform_scope") == "identity_provider"
    ]
    for mapping in mappings:
        mapping.update(
            {
                "url": "https://attack.mitre.org/techniques/"
                + mapping["technique_id"].replace(".", "/")
                + "/",
                "snapshot_date": "2026-09-27",
                "rationale": rule["rationale"],
            }
        )
    # Multi-user source rules do not acquire a spurious user identity from the last event.
    user = last.get("actor.user_id") if "actor.user_id" in rule["aggregate"]["group_by"] else None
    return {
        "id": "ALT-" + digest([rule["id"], rule["version"], group_key, last.uid])[:24],
        "rule_id": rule["id"],
        "rule_version": rule["version"],
        "title": rule["title"],
        "severity": rule["severity"],
        "tenant_id": last.get("tenant.id"),
        "application_id": last.get("app.id"),
        "user_id": user,
        "client_ip": last.get("network.client_ip"),
        "group_key": list(group_key),
        "start": first.time,
        "end": last.time,
        "episode_started": last.time,
        "evidence_ids": list(dict.fromkeys(e.uid for e in events)),
        "upstream_alert_ids": upstream or [],
        "attack": mappings,
        "alternatives": rule["false_positives"],
        "next_steps": rule["next_steps"],
        "limitations": ["Observed behavior requires analyst review; compromise is not established."],
        "metrics": {},
        "suppressed": False,
        "context_ids": [],
        "confidence": "limited"
        if any(e.flags or e.get("source.authority") == "unverified" for e in events)
        else "supported",
    }


def detect(
    events: Iterable[Event], rules: list[dict], config: Config, sources: list[Source]
) -> tuple[list[dict], list[dict], list[dict]]:
    indexed = {r["id"]: r for r in rules}
    states: dict[str, dict[tuple, Window]] = {r["id"]: {} for r in rules}
    expiry: dict[str, list[tuple]] = {r["id"]: [] for r in rules}
    last_seen: dict[str, dict[tuple, int]] = {r["id"]: {} for r in rules}
    alerts: list[dict] = []
    findings: list[dict] = []
    quality = {
        r["id"]: {"rule_id": r["id"], "candidates": 0, "eligible": 0, "missing_fields": Counter()}
        for r in rules
    }
    capabilities = set(c for s in sources for c in s.declared_capabilities)
    downstream: dict[str, list[dict]] = {}
    for r in rules:
        if r["aggregate"]["type"] == "sequence":
            downstream.setdefault(r["aggregate"]["upstream"], []).append(r)
    sequence_history: dict[str, dict[tuple, tuple[Event, dict, list[str], int]]] = {
        r["id"]: {} for r in rules
    }
    sequence_episodes: dict[str, dict[tuple, tuple[dict, set[str]]]] = {r["id"]: {} for r in rules}
    heartbeats: dict[str, list[int]] = {}
    serial = 0
    previous: tuple[int, str] | None = None
    dispatch: dict[str | None, list[dict]] = {}
    for rule in rules:
        terms = rule["select"].get("all", [rule["select"]])
        action = next(
            (
                t["equals"]
                for t in terms
                if t.get("field") == "event.action" and isinstance(t.get("equals"), str)
            ),
            None,
        )
        dispatch.setdefault(action, []).append(rule)
    for event in events:
        serial += 1
        if previous and (event.time, event.uid) < previous:
            raise LiaError("events_not_sorted", 4)
        previous = event.time, event.uid
        if event.get("event.action") == "source.heartbeat":
            heartbeats.setdefault(event.source_id, []).append(event.time)
        for rule in dispatch.get(event.get("event.action"), []) + dispatch.get(None, []):
            rid = rule["id"]
            aggregate = rule["aggregate"]
            selected = evaluate(rule["select"], event) is True
            if rid == "DET-007":
                selected = selected and event.get("http.path") in config.sensitive_paths
            if not selected:
                continue
            q = quality[rid]
            q["candidates"] += 1
            if not eligible(event, rule):
                for f in rule["required_fields"]:
                    if event.get(f) is None or event.get(f) == "":
                        q["missing_fields"][f] += 1
                if event.uncertainty > 30000000:
                    q["missing_fields"]["event.time_quality"] += 1
                continue
            q["eligible"] += 1
            key = tuple(event.get(f) for f in aggregate["group_by"])
            if aggregate["type"] == "sequence":
                upstream = indexed[aggregate["upstream"]]
                up_id = upstream["id"]
                match = tuple(event.get(f) for f in aggregate["match_fields"])
                if any(v is None or v == "" for v in match):
                    continue
                if upstream["aggregate"]["type"] != "sequence":
                    up_key = tuple(event.get(f) for f in upstream["aggregate"]["group_by"])
                    state = states[up_id].get(up_key)
                    if not state or state.last_qualifying is None or not state.last_event or not state.alert:
                        continue
                    before, parent = state.last_event, state.alert
                    candidate_start = state.qualifying_start
                    candidate_upper = state.qualifying_upper
                    # Snapshot is only copied when a subsequent nonqualifying failure could evict it.
                    evidence = (
                        list(state.qualifying_ids)
                        if state.qualifying_ids is not None
                        else [e.uid for e in state.events]
                    )
                else:
                    record = sequence_history[up_id].get(match)
                    if not record:
                        continue
                    before, parent, evidence, candidate_start = record
                    candidate_upper = before.interval[1]
                gap = event.time - before.time
                if gap < 0 or gap > duration(aggregate["max_gap"]):
                    continue
                if not ordered(before, event) or candidate_upper >= event.interval[0]:
                    findings.append(
                        {"code": "order_unverified", "rule_id": rid, "event_ids": [before.uid, event.uid]}
                    )
                    continue
                if rid == "DET-006" and event.get("actor.user_id") != event.get("target.user_id"):
                    continue
                candidate_evidence = list(dict.fromkeys(evidence + [event.uid]))
                episode = sequence_episodes[rid].get(key)
                if (
                    episode
                    and event.time - episode[0]["episode_started"] <= HOUR
                    and any(uid in episode[1] for uid in evidence)
                ):
                    alert, known = episode
                    alert["evidence_ids"].extend(uid for uid in candidate_evidence if uid not in known)
                    known.update(candidate_evidence)
                    alert["end"] = event.time
                    if parent["id"] not in alert["upstream_alert_ids"]:
                        alert["upstream_alert_ids"].append(parent["id"])
                else:
                    episodes = sequence_episodes[rid]
                    if key not in episodes and len(episodes) >= config.limits.max_groups:
                        for stale in [k for k, v in episodes.items() if event.time - v[0]["end"] > HOUR]:
                            del episodes[stale]
                        if len(episodes) >= config.limits.max_groups:
                            raise LiaError("active_group_limit", 4)
                    alert = new_alert(rule, key, [before, event], config, [parent["id"]])
                    alert["start"] = candidate_start
                    alert["evidence_ids"] = candidate_evidence
                    sequence_episodes[rid][key] = (alert, set(candidate_evidence))
                    alerts.append(alert)
                for child in downstream.get(rid, []):
                    child_key = tuple(event.get(f) for f in child["aggregate"]["match_fields"])
                    if all(v is not None and v != "" for v in child_key):
                        history = sequence_history[rid]
                        if child_key not in history and len(history) >= config.limits.max_groups:
                            retention = max(duration(c["aggregate"]["max_gap"]) for c in downstream[rid])
                            for stale in [
                                k for k, v in history.items() if event.time - v[0].time > retention
                            ]:
                                del history[stale]
                            if len(history) >= config.limits.max_groups:
                                raise LiaError("active_group_limit", 4)
                        sequence_history[rid][child_key] = (event, alert, candidate_evidence, candidate_start)
                continue
            window = duration(aggregate["window"])
            retention = window + max(
                [duration(r["aggregate"]["max_gap"]) for r in downstream.get(rid, [])] or [0]
            )
            heap = expiry[rid]
            while heap and heap[0][0] < event.time - retention:
                stamp, _, stale_key = heapq.heappop(heap)
                if last_seen[rid].get(stale_key) == stamp:
                    states[rid].pop(stale_key, None)
                    last_seen[rid].pop(stale_key, None)
            if key not in states[rid]:
                if len(states[rid]) >= config.limits.max_groups:
                    raise LiaError("active_group_limit", 4)
                states[rid][key] = Window()
            state = states[rid][key]
            last_seen[rid][key] = event.time
            heapq.heappush(heap, (event.time, serial, key))
            fields = (
                [aggregate["field"]]
                if aggregate["type"] == "distinct_count"
                else [m["field"] for m in aggregate.get("measures", []) if m["field"]]
            )
            # Preserve the most recent qualifying window if it is about to become ineligible.
            if downstream.get(rid) and state.last_qualifying is not None and state.qualifying_ids is None:
                if state.events and state.events[0].time <= event.time - window:
                    state.qualifying_ids = tuple(e.uid for e in state.events)
            while state.events and state.events[0].time <= event.time - window:
                old = state.events.popleft()
                if state.bounds and state.bounds[0][0] == old.uid:
                    state.bounds.popleft()
                state.first_index += 1
                for f in fields:
                    state.counts[f][old.get(f)] -= 1
                    if state.counts[f][old.get(f)] == 0:
                        del state.counts[f][old.get(f)]
            state.events.append(event)
            while state.bounds and state.bounds[-1][1] <= event.interval[1]:
                state.bounds.pop()
            state.bounds.append((event.uid, event.interval[1]))
            state.next_index += 1
            for f in fields:
                state.counts.setdefault(f, Counter())[event.get(f)] += 1
            metrics = {"events": len(state.events)}
            if aggregate["type"] == "event_count":
                match_ok = len(state.events) >= aggregate["threshold"]["gte"]
            elif aggregate["type"] == "distinct_count":
                metrics["distinct"] = len(state.counts[aggregate["field"]])
                match_ok = metrics["distinct"] >= aggregate["threshold"]["gte"]
            else:
                for measure in aggregate["measures"]:
                    metrics[measure["name"]] = (
                        len(state.counts[measure["field"]]) if measure["field"] else len(state.events)
                    )
                match_ok = all(metrics[m["name"]] >= m["threshold"]["gte"] for m in aggregate["measures"])
            if not match_ok:
                continue
            if (
                not state.alert
                or state.first_index > state.last_index
                or event.time - state.alert["episode_started"] > HOUR
            ):
                state.alert = new_alert(rule, key, list(state.events), config)
                alerts.append(state.alert)
            else:
                if state.next_index - state.last_index == 2:
                    state.alert["evidence_ids"].append(event.uid)
                else:
                    # A temporarily nonqualifying window can regain its threshold.
                    # Include every newly contributing event, not only the last trigger.
                    state.alert["evidence_ids"].extend(
                        e.uid
                        for index, e in enumerate(state.events, state.first_index)
                        if index > state.last_index
                    )
                state.alert["end"] = event.time
                if event.flags or event.get("source.authority") == "unverified":
                    state.alert["confidence"] = "limited"
            state.alert["metrics"] = metrics
            state.last_index = state.next_index - 1
            state.last_qualifying = event.time
            state.last_event = event
            state.qualifying_ids = None
            state.qualifying_start = state.events[0].time
            # Only downstream rules need uncertainty bounds; the dense count path stays O(1).
            state.qualifying_upper = state.bounds[0][1]
    reports = []
    for rule in rules:
        q = quality[rule["id"]]
        declared = set(rule["required_capabilities"]) <= capabilities
        if q["eligible"] == 0:
            status = "no_data" if q["candidates"] == 0 and declared else "unavailable"
        elif q["eligible"] < q["candidates"] or not declared:
            status = "degraded"
        else:
            status = "ready"
        q.update(
            {
                "status": status,
                "excluded": q["candidates"] - q["eligible"],
                "eligible_percent": 100 * q["eligible"] / q["candidates"] if q["candidates"] else None,
                "missing_fields": dict(q["missing_fields"]),
                "required_capabilities": rule["required_capabilities"],
                "recommendation": "Record the required fields and explicit outcomes; missing observations do not establish safety.",
            }
        )
        reports.append(q)
    for source in sources:
        if not source.heartbeat:
            continue
        hb = source.heartbeat
        start, end = parse_time(hb.coverage_start)[0], parse_time(hb.coverage_end)[0]
        if start >= end:
            raise LiaError("invalid_heartbeat_coverage")
        points = (
            [start] + sorted(t for t in heartbeats.get(source.source_id, []) if start <= t <= end) + [end]
        )
        for a, b in zip(points, points[1:]):
            if b - a > hb.max_gap_s * 1000000:
                findings.append(
                    {"code": "heartbeat_gap", "source_id": source.source_id, "start": a, "end": b}
                )
    return sorted(alerts, key=lambda a: (a["start"], a["id"])), reports, findings
