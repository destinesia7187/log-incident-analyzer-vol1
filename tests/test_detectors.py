"""Eight independently specified positive/negative contracts per detector."""

import pytest


def variants(prefix):
    return [
        pytest.param(i, id=f"{prefix}-{i:03}", marks=pytest.mark.case(f"{prefix}-{i:03}"))
        for i in range(1, 9)
    ]


def find(result, rid):
    return [a for a in result[0] if a["rule_id"] == rid]


@pytest.mark.parametrize("variant", variants("D01"))
def test_det001(variant, event, detect_events):
    n = 9 if variant == 2 else 10
    values = [
        event(
            i,
            i * (70 if variant == 3 else 10),
            user=None if variant == 7 else f"user-{i % 2}" if variant == 5 else "owner",
            address=f"192.0.2.{i % 2 + 1}" if variant == 6 else "192.0.2.1",
            outcome="unknown" if variant == 4 and i == 9 else "failure",
        )
        for i in range(n)
    ]
    result = detect_events(values)
    alerts = find(result, "DET-001")
    assert bool(alerts) == (variant in (1, 8))
    if alerts:
        assert len(alerts[0]["evidence_ids"]) == 10 and alerts[0]["severity"] == "medium"
        assert alerts[0]["attack"][0]["technique_id"] == "T1110.001"
    if variant == 7:
        q = next(q for q in result[1] if q["rule_id"] == "DET-001")
        assert q["status"] == "unavailable" and q["excluded"] == 10


@pytest.mark.parametrize("variant", variants("D02"))
def test_det002(variant, event, detect_events):
    n = 100 if variant == 2 else 20 if variant == 3 else 11 if variant == 6 else 10
    values = [
        event(
            i,
            i,
            user=f"u{i % 9}" if variant == 2 else "one" if variant == 3 else f"u{i % 10}",
            address=None if variant == 8 else f"192.0.2.{i % 2 + 1}" if variant == 4 else "192.0.2.1",
        )
        for i in range(n)
    ]
    alerts = find(detect_events(values), "DET-002")
    assert bool(alerts) == (variant in (1, 5, 6, 7))
    if alerts:
        assert alerts[0]["metrics"]["distinct"] == 10
        assert all(m["mapping_status"] == "candidate" for m in alerts[0]["attack"])
        assert "Password equality is not observed" in alerts[0]["alternatives"][0]
        assert alerts[0]["user_id"] is None


@pytest.mark.parametrize("variant", variants("D03"))
def test_det003(variant, event, source, detect_events):
    src = source.model_copy(update={"clock_uncertainty_ms": 2000}) if variant == 7 else source
    n = 20 if variant == 8 else 10
    values = [event(i, i, source_override=src) for i in range(n)]
    when = 0 if variant == 2 else 609.000001 if variant == 5 else 10 if variant == 7 else 100
    values.append(
        event(
            99,
            when,
            source_override=src,
            action="http.request" if variant == 6 else "auth.login",
            outcome="success",
            user="other" if variant == 3 else "demo-user",
            address="192.0.2.20" if variant == 4 else "192.0.2.10",
        )
    )
    result = detect_events(values)
    alerts = find(result, "DET-003")
    assert bool(alerts) == (variant in (1, 8))
    if alerts:
        assert len(alerts[0]["evidence_ids"]) == n + 1 and alerts[0]["severity"] == "high"
        assert set(e.uid for e in values) == set(alerts[0]["evidence_ids"])
    if variant == 7:
        assert any(f["code"] == "order_unverified" for f in result[2])


@pytest.mark.parametrize("variant", variants("D04"))
def test_det004(variant, event, source, detect_events):
    n = 19 if variant == 2 else 20
    values = []
    for i in range(n):
        address = f"192.0.2.{i % (4 if variant == 3 else 5) + 1}"
        if variant == 5:
            address = [
                "2001:db8::1",
                "2001:0db8::1",
                "2001:db8:0::1",
                "2001:db8:0:0::1",
                "2001:db8:0:0:0::1",
            ][i % 5]
        if variant == 7 and i % 5 == 4:
            address = "invalid"
        src = source.model_copy(update={"tenant_id": f"t{i % 2}"}) if variant == 6 else source
        values.append(
            event(i, i, user=f"u{i % 2}" if variant == 4 else "u", address=address, source_override=src)
        )
    alerts = find(detect_events(values), "DET-004")
    assert bool(alerts) == (variant in (1, 8))
    if alerts:
        assert alerts[0]["metrics"] == {"events": 20, "distinct_ips": 5}
        assert [m["technique_id"] for m in alerts[0]["attack"]] == ["T1110"]


@pytest.mark.parametrize("variant", variants("D05"))
def test_det005(variant, event, detect_events):
    n = 4 if variant == 2 else 5
    values = [
        event(
            i,
            i * (100 if variant == 6 else 10),
            action="auth.mfa.enroll" if variant == 7 else "auth.mfa.challenge",
            outcome="success" if variant == 7 else "requested",
            user=f"u{i % 2}" if variant == 5 else "u",
            auth={} if variant == 4 else {"mfa_request_id": "one" if variant == 3 else f"challenge-{i}"},
        )
        for i in range(n)
    ]
    if variant == 8:
        values.append(event(100, 60, action="auth.mfa.challenge", outcome="success", user="u"))
    alerts = find(detect_events(values), "DET-005")
    assert bool(alerts) == (variant in (1, 8))
    if alerts:
        assert len(alerts[0]["evidence_ids"]) == 5
        assert alerts[0]["attack"][0]["technique_id"] == "T1621"


@pytest.mark.parametrize("variant", variants("D06"))
def test_det006(variant, event, source, detect_events):
    src = source.model_copy(update={"platform_scope": "generic_application"}) if variant == 8 else source
    values = [] if variant == 2 else [event(i, i, source_override=src) for i in range(10)]
    values.append(
        event(
            20,
            100,
            outcome="success",
            auth={} if variant == 3 else {"session_ref": "session-1"},
            source_override=src,
        )
    )

    def enrol(seconds=120):
        return event(
            21,
            seconds,
            action="auth.mfa.enroll",
            outcome="success",
            user="admin" if variant == 7 else "demo-user",
            target={"user_id": "demo-user"},
            auth={"session_ref": "session-2" if variant == 4 else "session-1", "device_ref": "device-2"},
            source_override=src,
        )

    values.append(enrol(99 if variant == 5 else 1000 if variant == 6 else 120))
    alerts = find(detect_events(values), "DET-006")
    assert bool(alerts) == (variant in (1, 6, 8))
    if alerts:
        assert len(alerts[0]["evidence_ids"]) == 12 and alerts[0]["severity"] == "high"
        assert bool(alerts[0]["attack"]) == (variant != 8)
    if variant == 6:
        assert not find(detect_events(values[:-1] + [enrol(1000.000001)]), "DET-006")


@pytest.mark.parametrize("variant", variants("D07"))
def test_det007(variant, event, detect_events):
    paths = ["/.env", "/.git/config", "/admin", "/backup.zip", "/config"]
    n = 50 if variant == 2 else 4 if variant == 3 else 10 if variant == 4 else 5
    values = []
    for i in range(n):
        path = "/.env" if variant == 2 else f"/ordinary/{i}" if variant == 4 else paths[i % 5]
        if variant == 8:
            path = path.replace(".", "%2e")
        values.append(
            event(
                i,
                i,
                action="http.request",
                outcome="unknown",
                address=f"192.0.2.{i % 2 + 1}" if variant == 5 else "192.0.2.1",
                http={"method": "GET", "path": path, "status": [200, 302, 401, 403, 404][i % 5]},
            )
        )
    alerts = find(detect_events(values), "DET-007")
    assert bool(alerts) == (variant in (1, 6, 7, 8))
    if alerts:
        assert alerts[0]["metrics"]["distinct"] == 5 and alerts[0]["attack"] == []
        assert "does not prove data disclosure" in alerts[0]["alternatives"][0]


@pytest.mark.parametrize("variant", variants("D08"))
def test_det008(variant, event, detect_events):
    n = 9 if variant == 2 else 10
    values = [
        event(
            i,
            i,
            action="http.request" if variant == 7 else "authz.check",
            outcome="unknown" if variant == 7 else "success" if variant == 4 and i == 9 else "denied",
            user=f"u{i % 2}" if variant == 6 else "u",
            target={} if variant == 5 else {"resource_id": f"r{i % (2 if variant == 3 else 3)}"},
            http={"status": 403},
        )
        for i in range(n)
    ]
    alerts = find(detect_events(values), "DET-008")
    assert bool(alerts) == (variant in (1, 8))
    if alerts:
        assert alerts[0]["metrics"] == {"events": 10, "distinct_resources": 3}
        assert "does not prove IDOR" in alerts[0]["alternatives"][0] and not alerts[0]["attack"]
