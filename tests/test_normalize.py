import pytest

from lia.common import LiaError
from lia.config import Config
from lia.demo import raw_event
from lia.normalize import ip, normalize


@pytest.mark.case("NRM-001")
def test_ipv4():
    assert ip("192.0.2.1") == "192.0.2.1"
    assert ip("300.0.0.1") is None


@pytest.mark.case("NRM-002")
def test_ipv6():
    assert ip("2001:0db8:0000:0000:0000:0000:0000:0001") == ip("2001:db8::1")


@pytest.mark.case("NRM-003")
def test_mapped():
    assert ip("::ffff:192.0.2.1") == "192.0.2.1"


@pytest.mark.case("NRM-004")
def test_http_status(event):
    assert event(http={"status": 200}).get("http.status") == 200
    bad = event(http={"status": "abc"})
    assert bad.get("http.status") is None and "invalid:http.status" in bad.flags


@pytest.mark.case("NRM-005")
def test_case_sensitive(event):
    assert event(user="Alice").get("actor.user_id") != event(user="alice").get("actor.user_id")


@pytest.mark.case("NRM-006")
def test_unicode(event):
    assert event(user="а").get("actor.user_id") != event(user="a").get("actor.user_id")
    assert event(user="пользователь").get("actor.user_id") == "пользователь"


@pytest.mark.case("NRM-007")
@pytest.mark.parametrize("value", [None, "", 12])
def test_missing_user(event, value):
    assert event(user=value).get("actor.user_id") is None


@pytest.mark.case("NRM-008")
def test_literal_null(event):
    assert event(user="null").get("actor.user_id") == "null"


@pytest.mark.case("NRM-009")
def test_bad_pair(event):
    with pytest.raises(LiaError, match="invalid_action_outcome"):
        event(outcome="requested")


@pytest.mark.case("NRM-010")
@pytest.mark.parametrize("status", [200, 302])
def test_http_not_auth(source, status):
    raw = {"timestamp": "2026-01-15T12:00:00Z", "http": {"status": status, "path": "/login"}}
    e = normalize(raw, source.model_copy(update={"format": "nginx-json-v1"}), Config(), b"k")
    assert e.get("event.action") == "http.request" and e.get("event.outcome") == "unknown"


@pytest.mark.case("NRM-011")
def test_actor_target(event):
    e = event(user="admin", target={"user_id": "victim"})
    assert e.get("actor.user_id") == "admin" and e.get("target.user_id") == "victim"


@pytest.mark.case("NRM-012", "NRM-013")
@pytest.mark.parametrize("field", ["tenant_id", "application_id"])
def test_namespaces(event, source, field):
    assert event().uid != event(source_override=source.model_copy(update={field: "other"})).uid


@pytest.mark.case("NRM-014")
def test_query_removed(event):
    e = event(http={"path": "/admin?token=CANARY"})
    assert e.get("http.path") == "/admin" and "CANARY" not in str(e.payload())


@pytest.mark.case("NRM-015")
def test_single_decode(event):
    assert event(http={"path": "/%252eenv"}).get("http.path") == "/%2eenv"


@pytest.mark.case("NRM-016")
def test_unknown_fields(source):
    e = normalize(
        {**raw_event(0), "extra": {"password": "CANARY"}, "free_text": "CANARY"}, source, Config(), b"k"
    )
    assert "CANARY" not in str(e.payload()) and "unknown_fields" in e.flags


@pytest.mark.case("NRM-017")
def test_field_limits(source, event):
    assert event(user="x" * 4097).get("actor.user_id") is None
    with pytest.raises(LiaError, match="field_too_long"):
        normalize({**raw_event(0), "event_id": "x" * 4097}, source, Config(), b"k")


@pytest.mark.case("NRM-018")
def test_untrusted_forwarded(source):
    e = normalize(
        raw_event(0, network={"peer_ip": "192.0.2.1", "forwarded_for": "198.51.100.1"}),
        source,
        Config(),
        b"k",
    )
    assert e.get("network.client_ip") == "192.0.2.1"


@pytest.mark.case("NRM-019")
def test_trusted_chain(source):
    source = source.model_copy(update={"forwarded_enabled": True})
    e = normalize(
        raw_event(0, network={"peer_ip": "10.0.0.1", "forwarded_for": "203.0.113.1, 198.51.100.1, 10.0.0.2"}),
        source,
        Config(trusted_proxy_cidrs=["10.0.0.0/8"]),
        b"k",
    )
    assert e.get("network.client_ip") == "198.51.100.1"


@pytest.mark.case("NRM-020")
def test_bad_forwarded(source):
    source = source.model_copy(update={"forwarded_enabled": True})
    e = normalize(
        raw_event(0, network={"peer_ip": "10.0.0.1", "forwarded_for": "invalid"}),
        source,
        Config(trusted_proxy_cidrs=["10.0.0.0/8"]),
        b"k",
    )
    assert e.get("network.client_ip") == "10.0.0.1" and "invalid_forwarded" in e.flags
