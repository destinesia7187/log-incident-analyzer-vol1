from copy import deepcopy

from lia.evaluation import metrics


def test_requalified_window_preserves_intermediate_evidence(event, detect_events):
    # Ten failures qualify; two old events then expire. A later pair restores
    # the threshold while the windows still overlap and belong to one episode.
    values = [event(i, i) for i in range(10)] + [event(10, 301), event(11, 301.1)]
    result = [a for a in detect_events(values)[0] if a["rule_id"] == "DET-001"]
    assert len(result) == 1
    assert set(result[0]["evidence_ids"]) == {e.uid for e in values}


def test_duplicate_alert_count_is_not_candidate_pair_count():
    episode = {
        "id": "e1",
        "label": "attack",
        "eligible": True,
        "tenant_id": "t",
        "application_id": "a",
        "entity_field": "user_id",
        "entity_value": "u",
        "primary_rules": ["D"],
        "relevant_event_ids": ["x"],
        "start": 0,
        "end": 10,
    }
    second = {**deepcopy(episode), "id": "e2"}
    alerts = [
        {
            "id": f"a{i}",
            "rule_id": "D",
            "tenant_id": "t",
            "application_id": "a",
            "user_id": "u",
            "evidence_ids": ["x"],
            "start": 0,
            "end": 10,
        }
        for i in range(3)
    ]
    result = metrics(alerts, [episode, second])
    assert (result["tp"], result["fp"], result["duplicate_alerts"]) == (2, 1, 1)
