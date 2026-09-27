import random

import pytest

from lia.common import LiaError, digest
from lia.normalize import parse_time


def ids(result):
    return {a["rule_id"] for a in result[0]}


@pytest.mark.case("TIM-001")
def test_offsets():
    assert parse_time("2026-01-01T12:00:00+05:00")[0] == parse_time("2026-01-01T07:00:00Z")[0]


@pytest.mark.case("TIM-002")
def test_timezone():
    assert parse_time("2026-01-01T12:00:00", "Asia/Qyzylorda")[0] == parse_time("2026-01-01T07:00:00Z")[0]


@pytest.mark.case("TIM-003")
def test_no_zone():
    with pytest.raises(LiaError, match="timezone_required"):
        parse_time("2026-01-01T12:00:00")


@pytest.mark.case("TIM-004")
def test_ambiguous():
    with pytest.raises(LiaError, match="ambiguous_time"):
        parse_time("2026-11-01T01:30:00", "America/New_York")


@pytest.mark.case("TIM-005")
def test_nonexistent():
    with pytest.raises(LiaError, match="nonexistent_time"):
        parse_time("2026-03-08T02:30:00", "America/New_York")


@pytest.mark.case("TIM-006", "TIM-007", "TIM-008")
def test_boundaries(event, detect_events):
    failures = [event(i, 1 + i) for i in range(9)]
    assert "DET-001" not in ids(detect_events([event(20, 0)] + [event(i, 300) for i in range(9)]))
    assert "DET-001" in ids(detect_events([event(20, 0.000001)] + [event(i, 300) for i in range(9)]))
    assert "DET-001" in ids(detect_events(failures + [event(20, 300)]))


@pytest.mark.case("TIM-009")
def test_midnight(event, detect_events):
    values = [event(i, 43195 + i) for i in range(10)]
    assert "DET-001" in ids(detect_events(values))


@pytest.mark.case("TIM-010")
def test_order(event, detect_events):
    values = [event(i, i) for i in range(100)]
    expected = digest(detect_events(values))
    random.Random(42).shuffle(values)
    assert digest(detect_events(values)) == expected


@pytest.mark.case("TIM-012", "TIM-019")
@pytest.mark.parametrize("success_time", [0, 9])
def test_order_not_invented(event, detect_events, success_time):
    values = [event(i, i) for i in range(10)]
    # Exercise the case where deterministic UID ordering puts the success last.
    # That arbitrary tie-break must never become evidence of temporal order.
    success = next(
        candidate
        for i in range(20, 1000)
        if (candidate := event(i, success_time, outcome="success")).uid > values[-1].uid
    )
    values.append(success)
    assert "DET-003" not in ids(detect_events(values))


@pytest.mark.case("TIM-013")
def test_clock_offset(event, source):
    original = event()
    shifted = event(source_override=source.model_copy(update={"clock_offset_ms": -60000}))
    assert shifted.time == original.time - 60000000
    assert shifted.get("event.time_original") == original.get("event.time_original")


@pytest.mark.case("TIM-014")
def test_uncertain_sequence(event, source, detect_events):
    src = source.model_copy(update={"clock_uncertainty_ms": 2000})
    values = [event(i, i, source_override=src) for i in range(10)] + [
        event(20, 10, outcome="success", source_override=src)
    ]
    a, _, findings = detect_events(values)
    assert "DET-003" not in {x["rule_id"] for x in a}
    assert any(f["code"] == "order_unverified" for f in findings)


@pytest.mark.case("TIM-015", "TIM-016")
@pytest.mark.parametrize("uncertainty,matched", [(30001, False), (30000, True)])
def test_uncertainty_limit(event, source, detect_events, uncertainty, matched):
    values = [
        event(i, i, source_override=source.model_copy(update={"clock_uncertainty_ms": uncertainty}))
        for i in range(10)
    ]
    result = detect_events(values)
    assert ("DET-001" in ids(result)) is matched
    if matched:
        assert result[0][0]["confidence"] == "limited"


@pytest.mark.case("TIM-017")
def test_precision(event, source, detect_events):
    src = source.model_copy(update={"precision_us": 1000000})
    values = [event(i, i / 100, source_override=src) for i in range(10)] + [
        event(20, 0.2, outcome="success", source_override=src)
    ]
    assert "DET-003" not in ids(detect_events(values))


@pytest.mark.case("TIM-018")
@pytest.mark.parametrize("gap,matched", [(600, True), (600.000001, False)])
def test_sequence_gap(event, detect_events, gap, matched):
    values = [event(i, i) for i in range(10)] + [event(20, 9 + gap, outcome="success")]
    assert ("DET-003" in ids(detect_events(values))) is matched


@pytest.mark.case("TIM-020")
def test_episode_limit(event, detect_events):
    values = [event(i, i * 20) for i in range(200)]
    a = [a for a in detect_events(values)[0] if a["rule_id"] == "DET-001"]
    assert len(a) == 2
    assert all(x["end"] - x["episode_started"] <= 3600000000 for x in a)
