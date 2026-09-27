"""Normalize allowlisted values. No source text is retained."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote, urlsplit
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .common import LiaError, depth, digest
from .config import Config, Source

EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
PAIRS = {
    "auth.login": {"success", "failure", "unknown"},
    "auth.mfa.challenge": {"requested", "success", "denied", "unknown"},
    "auth.mfa.enroll": {"success", "failure", "unknown"},
    "auth.password.reset": {"success", "failure", "requested", "unknown"},
    "authz.check": {"success", "denied", "unknown"},
    "http.request": {"success", "failure", "unknown"},
    "source.heartbeat": {"success"},
}


def parse_time(value: str, timezone: str | None = None) -> tuple[int, int]:
    if not isinstance(value, str):
        raise LiaError("invalid_time")
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if "T" not in value and " " not in value:
            raise ValueError("date only")
        if dt.tzinfo is None:
            if timezone is None:
                raise LiaError("timezone_required")
            zone = ZoneInfo(timezone)
            candidates = [dt.replace(tzinfo=zone, fold=f) for f in (0, 1)]
            valid = [c for c in candidates if c.astimezone(UTC).astimezone(zone).replace(tzinfo=None) == dt]
            if not valid:
                raise LiaError("nonexistent_time")
            if len({c.utcoffset() for c in valid}) > 1:
                raise LiaError("ambiguous_time")
            dt = valid[0]
        delta = dt.astimezone(UTC) - EPOCH
        us = (delta.days * 86400 + delta.seconds) * 1000000 + delta.microseconds
        fraction = re.search(r":\d\d\.(\d+)", value)
        precision = 10 ** (6 - min(6, len(fraction[1]))) if fraction else 1000000
        return us, precision
    except (ValueError, ZoneInfoNotFoundError, OverflowError) as exc:
        raise LiaError("invalid_time") from exc


def ip(value: Any) -> str | None:
    try:
        if not isinstance(value, str) or "%" in value:
            return None
        addr = ipaddress.ip_address(value)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return None


@dataclass(slots=True)
class Event:
    uid: str
    time: int
    data: dict[str, Any]
    source_id: str
    artifact: str
    line: int
    offset: int
    record_digest: str
    precision: int = 1
    uncertainty: int = 0
    flags: list[str] = field(default_factory=list)

    def get(self, name: str) -> Any:
        return self.data.get(name)

    @property
    def interval(self) -> tuple[int, int]:
        return self.time - self.uncertainty, self.time + self.uncertainty + self.precision - 1

    def payload(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "time": self.time,
            "fields": self.data,
            "source_id": self.source_id,
            "artifact": self.artifact,
            "line": self.line,
            "offset": self.offset,
            "record_digest": self.record_digest,
            "precision_us": self.precision,
            "uncertainty_us": self.uncertainty,
            "flags": self.flags,
        }


def text_field(value: Any, flags: list[str], name: str, required: bool = False) -> str | None:
    if not isinstance(value, str) or not value:
        if required:
            raise LiaError("missing_" + name)
        if value is not None:
            flags.append("invalid:" + name)
        return None
    if len(value) > 4096:
        if required:
            raise LiaError("field_too_long")
        flags.append("invalid:" + name)
        return None
    return value


def client_ip(
    peer: str | None, forwarded: Any, source: Source, config: Config, flags: list[str]
) -> tuple[str | None, str]:
    nets = [ipaddress.ip_network(n) for n in config.trusted_proxy_cidrs]

    def trusted(addr: str) -> bool:
        return any(ipaddress.ip_address(addr) in n for n in nets)

    if not peer or not source.forwarded_enabled or not trusted(peer) or not forwarded:
        return peer, "peer"
    if not isinstance(forwarded, str) or len(forwarded) > 4096:
        flags.append("invalid_forwarded")
        return peer, "peer"
    chain = [ip(x.strip()) for x in forwarded.split(",")] + [peer]
    if any(a is None for a in chain):
        flags.append("invalid_forwarded")
        return peer, "peer"
    for address in reversed(chain):
        if address and not trusted(address):
            return address, "trusted_proxy_chain"
    flags.append("no_untrusted_forwarded_hop")
    return peer, "peer"


def normalize(
    raw: dict,
    source: Source,
    config: Config,
    key: bytes,
    artifact: str = "fixture",
    line: int = 1,
    offset: int = 0,
    record_digest: str = "fixture",
) -> Event:
    depth(raw)
    if not isinstance(raw, dict):
        raise LiaError("record_not_object")
    flags: list[str] = []
    is_app = source.format == "app-audit-v1"
    if is_app and raw.get("schema_version") != "app-audit-v1":
        raise LiaError("invalid_event_schema")
    original_id = text_field(raw.get("event_id"), flags, "event_id", is_app)
    stamp = text_field(raw.get("timestamp"), flags, "timestamp", True)
    time, precision = parse_time(stamp, source.timezone)  # type: ignore[arg-type]
    time += source.clock_offset_ms * 1000
    action = raw.get("action", "http.request" if not is_app else None)
    outcome = raw.get("outcome", "unknown" if not is_app else None)
    if action not in PAIRS or outcome not in PAIRS[action]:
        raise LiaError("invalid_action_outcome")
    allowed = {
        "schema_version",
        "event_id",
        "timestamp",
        "action",
        "outcome",
        "actor",
        "target",
        "network",
        "http",
        "auth",
        "reason_code",
    }
    if set(raw) - allowed:
        flags.append("unknown_fields")
    fields: dict[str, Any] = {
        "tenant.id": source.tenant_id,
        "app.id": source.application_id,
        "event.action": action,
        "event.outcome": outcome,
        "event.original_id": original_id,
        "event.time_original": stamp,
        "source.authority": source.authority,
        "source.platform_scope": source.platform_scope,
    }
    nested_allowed = {
        "actor": {"user_id", "role"},
        "target": {"user_id", "resource_id"},
        "network": {"peer_ip", "forwarded_for"},
        "http": {"method", "path", "status", "request_id"},
        "auth": {"session_ref", "session_id", "mfa_request_id", "factor_kind", "device_ref"},
    }
    for section, allowed_fields in nested_allowed.items():
        obj = raw.get(section, {})
        if not isinstance(obj, dict):
            flags.append("invalid:" + section)
            obj = {}
        if set(obj) - allowed_fields:
            flags.append("unknown_fields:" + section)
        for name in allowed_fields - {"session_id", "forwarded_for", "peer_ip", "status", "path"}:
            fields[section + "." + name] = text_field(obj.get(name), flags, section + "." + name)
    network = raw.get("network", {}) if isinstance(raw.get("network", {}), dict) else {}
    peer = ip(network.get("peer_ip"))
    if network.get("peer_ip") is not None and peer is None:
        flags.append("invalid:network.peer_ip")
    client, basis = client_ip(peer, network.get("forwarded_for"), source, config, flags)
    fields.update({"network.peer_ip": peer, "network.client_ip": client, "network.client_ip_basis": basis})
    for field_name in ("actor.user_id", "target.user_id"):
        if fields.get(field_name) and source.casefold_user:
            fields[field_name] = fields[field_name].casefold()
    http = raw.get("http", {}) if isinstance(raw.get("http", {}), dict) else {}
    status = http.get("status")
    if isinstance(status, int) and not isinstance(status, bool) and 100 <= status <= 599:
        fields["http.status"] = status
    elif status is not None:
        flags.append("invalid:http.status")
    pathname = text_field(http.get("path"), flags, "http.path")
    if pathname:
        try:
            safe_path = urlsplit(pathname).path
            fields["http.path_original"] = safe_path
            fields["http.path"] = unquote(safe_path, errors="strict")
        except (ValueError, UnicodeError):
            flags.append("invalid:http.path")
    auth = raw.get("auth", {}) if isinstance(raw.get("auth", {}), dict) else {}
    session = text_field(auth.get("session_id"), flags, "auth.session_id")
    if session:
        fields["auth.session_ref"] = hmac.new(key, session.encode(), hashlib.sha256).hexdigest()
    if source.rounding == "unknown":
        flags.append("unknown_time_rounding")
    if source.clock_uncertainty_ms:
        flags.append("time_uncertainty")
    namespace = [source.tenant_id, source.application_id, source.source_id]
    uid = digest(namespace + [original_id] if original_id else [artifact, line])
    fields = {k: v for k, v in fields.items() if v is not None}
    return Event(
        uid,
        time,
        fields,
        source.source_id,
        artifact,
        line,
        offset,
        record_digest,
        source.precision_us or precision,
        source.clock_uncertainty_ms * 1000,
        sorted(set(flags)),
    )
