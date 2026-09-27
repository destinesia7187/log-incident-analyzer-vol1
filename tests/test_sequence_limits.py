import pytest

from lia.common import LiaError
from lia.config import Config, Limits


def burst(event, index, seconds, user, session):
    return [event(index + i, seconds + i, user=user) for i in range(10)] + [
        event(index + 10, seconds + 20, user=user, outcome="success", auth={"session_ref": session})
    ]


def test_sequence_history_limit(event, detect_events, rules):
    selected = [r for r in rules if r["id"] in {"DET-001", "DET-003", "DET-006"}]
    events = burst(event, 0, 0, "u", "s1") + [
        event(30, 21, user="u", outcome="success", auth={"session_ref": "s2"})
    ]
    with pytest.raises(LiaError, match="active_group_limit"):
        detect_events(events, Config(limits=Limits(max_groups=1)), selected)


@pytest.mark.parametrize("delay,user", [(1000, "u"), (4000, "v")])
def test_sequence_history_and_episode_eviction(event, detect_events, rules, delay, user):
    selected = [r for r in rules if r["id"] in {"DET-001", "DET-003", "DET-006"}]
    events = burst(event, 0, 0, "u", "s1") + burst(event, 100, delay, user, "s2")
    alerts = detect_events(events, Config(limits=Limits(max_groups=1)), selected)[0]
    assert len([a for a in alerts if a["rule_id"] == "DET-003"]) == 2


def test_sequence_episode_limit(event, detect_events, rules):
    selected = [r for r in rules if r["id"] in {"DET-001", "DET-003"}]
    events = burst(event, 0, 0, "u", "s1") + burst(event, 100, 1000, "v", "s2")
    with pytest.raises(LiaError, match="active_group_limit"):
        detect_events(events, Config(limits=Limits(max_groups=1)), selected)
