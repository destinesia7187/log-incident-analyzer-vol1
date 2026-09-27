import copy

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lia.common import digest
from lia.config import Config
from lia.demo import raw_event
from lia.normalize import normalize
from lia.storage import Store

PROFILE = settings(
    max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)


@pytest.mark.case("PROP-001")
@PROFILE
@given(order=st.permutations(list(range(12))))
def test_permutation(event, detect_events, order):
    values = [event(i, i) for i in range(12)]
    assert digest(detect_events(values)) == digest(detect_events([values[i] for i in order]))


@pytest.mark.case("PROP-002")
@PROFILE
@given(repetitions=st.integers(1, 30))
def test_idempotent(event, repetitions):
    from pathlib import Path

    s = Store(Path(":memory:"))
    try:
        e = event()
        assert s.add(e)[0] == "accepted_unique"
        for _ in range(repetitions):
            assert s.add(e)[0] == "duplicate_rows"
        assert len(list(s.events())) == 1
    finally:
        s.close()


@pytest.mark.case("PROP-003")
@PROFILE
@given(n=st.integers(1, 25))
def test_tenant_independence(event, source, detect_events, n):
    values = [event(i, i) for i in range(12)]
    base = detect_events(values)[0]
    extra = [
        event(100 + i, i, source_override=source.model_copy(update={"tenant_id": "other"})) for i in range(n)
    ]
    actual = [a for a in detect_events(values + extra)[0] if a["tenant_id"] == "t1"]
    assert base == actual


@pytest.mark.case("PROP-004")
@PROFILE
@given(delta=st.integers(-100000, 100000))
def test_time_translation(event, detect_events, delta):
    values = [event(i, i) for i in range(12)]
    baseline = detect_events(values)[0]
    for e in values:
        e.time += delta * 1000000
    shifted = detect_events(values)[0]
    assert [a["evidence_ids"] for a in shifted] == [a["evidence_ids"] for a in baseline]
    assert [a["start"] - delta * 1000000 for a in shifted] == [a["start"] for a in baseline]


@pytest.mark.case("PROP-005")
@PROFILE
@given(n=st.integers(1, 30), higher=st.integers(11, 40))
def test_threshold_monotonicity(event, rules, detect_events, n, higher):
    values = [event(i, i) for i in range(n)]
    changed = copy.deepcopy(rules)
    changed[0]["aggregate"]["threshold"]["gte"] = higher
    base = any(a["rule_id"] == "DET-001" for a in detect_events(values)[0])
    actual = any(a["rule_id"] == "DET-001" for a in detect_events(values, custom_rules=changed)[0])
    assert not actual or base


@pytest.mark.case("PROP-006")
@PROFILE
@given(n=st.integers(0, 30))
def test_unrelated_extension(event, detect_events, n):
    values = [event(i, i) for i in range(12)]
    extra = [event(100 + i, 1000 + i, action="auth.password.reset", outcome="requested") for i in range(n)]
    assert detect_events(values)[0] == detect_events(values + extra)[0]


@pytest.mark.case("PROP-007")
@PROFILE
@given(user=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), min_size=1, max_size=40))
def test_roundtrip(event, user):
    from lia.common import canonical

    e = event(user=user)
    loaded = Store.decode(canonical(e.payload()))
    assert loaded.payload() == e.payload()


@pytest.mark.case("PROP-008")
@PROFILE
@given(secret=st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=8, max_size=40))
def test_redaction(source, secret):
    canary = "CANARY_" + secret
    raw = {
        **raw_event(0, auth={"session_id": canary}, http={"path": "/login?token=" + canary}),
        "password": canary,
        "Authorization": canary,
    }
    assert canary not in str(normalize(raw, source, Config(), b"k" * 32).payload())
