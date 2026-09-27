"""Strict configuration and bounded YAML loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .common import LiaError, depth, digest


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, populate_by_name=True)


class Limits(Strict):
    line_bytes: int = Field(262144, ge=1)
    max_files: int = Field(100, ge=1)
    input_bytes: int = Field(2 * 1024**3, ge=1)
    gzip_ratio: int = Field(100, ge=1)
    gzip_grace_bytes: int = Field(10 * 1024**2, ge=1)
    max_groups: int = Field(100000, ge=1)
    workspace_bytes: int = Field(16 * 1024**3, ge=1)


class Heartbeat(Strict):
    coverage_start: str
    coverage_end: str
    expected_interval_s: int = Field(gt=0)
    max_gap_s: int = Field(gt=0)

    @model_validator(mode="after")
    def gaps(self) -> Heartbeat:
        if self.max_gap_s < self.expected_interval_s:
            raise ValueError("heartbeat_interval")
        return self


class Source(Strict):
    path: str
    format: Literal["app-audit-v1", "nginx-json-v1", "nginx-combined-v1"]
    source_id: str = Field(min_length=1, max_length=256)
    tenant_id: str = Field(min_length=1, max_length=256)
    application_id: str = Field(min_length=1, max_length=256)
    authority: Literal["application_audit", "idp_audit", "web_access", "unverified"] = "unverified"
    platform_scope: str = "generic_application"
    declared_capabilities: list[str] = Field(default_factory=list)
    available_fields: list[str] = Field(default_factory=list)
    timezone: str | None = None
    casefold_user: bool = False
    clock_offset_ms: int = 0
    clock_uncertainty_ms: int = Field(0, ge=0)
    precision_us: int | None = Field(None, ge=1)
    rounding: Literal["truncate", "unknown"] = "truncate"
    forwarded_enabled: bool = False
    heartbeat: Heartbeat | None = None


class Manifest(Strict):
    schema_name: Literal["lia-input/v1"] = Field(alias="schema")
    input_root: str
    sources: list[Source] = Field(min_length=1)

    @model_validator(mode="after")
    def unique(self) -> Manifest:
        ids = [s.source_id for s in self.sources]
        # Source ID can repeat for rotation, but authority/namespace cannot change.
        for sid in set(ids):
            definitions = [s.model_dump(exclude={"path"}) for s in self.sources if s.source_id == sid]
            if any(d != definitions[0] for d in definitions):
                raise ValueError("inconsistent_source")
        return self


class ContextEntry(Strict):
    id: str = Field(min_length=1)
    kind: Literal["critical", "approved", "suppression", "nat"]
    tenant_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    user_id: str | None = None
    client_ip: str | None = None
    rule_id: str | None = None
    source: str = Field(min_length=1)
    author: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    created_at: str
    valid_from: str
    expires_at: str

    @model_validator(mode="after")
    def scope(self) -> ContextEntry:
        if "*" in [self.tenant_id, self.application_id, self.user_id, self.rule_id, self.client_ip]:
            raise ValueError("wildcard_context")
        if self.kind in ("approved", "suppression") and (
            not self.rule_id or not (self.user_id or self.client_ip)
        ):
            raise ValueError("context_scope_required")
        from .normalize import parse_time

        parse_time(self.created_at)
        if parse_time(self.valid_from)[0] >= parse_time(self.expires_at)[0]:
            raise ValueError("context_interval")
        return self


class Config(Strict):
    schema_name: Literal["lia-config/v1"] = Field("lia-config/v1", alias="schema")
    limits: Limits = Field(default_factory=Limits)
    trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    sensitive_paths: list[str] = Field(
        default_factory=lambda: ["/.env", "/.git/config", "/admin", "/backup.zip", "/config"]
    )
    context: list[ContextEntry] = Field(default_factory=list)
    enabled_rules: list[str] | None = None

    @model_validator(mode="after")
    def networks(self) -> Config:
        import ipaddress

        for net in self.trusted_proxy_cidrs:
            ipaddress.ip_network(net)
        ids = [c.id for c in self.context]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate_context")
        return self


class SafeLoader(yaml.SafeLoader):
    pass


def mapping(loader: SafeLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    output: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in output:
            raise LiaError("duplicate_or_nonstring_yaml_key")
        output[key] = loader.construct_object(value_node, deep=deep)
    return output


SafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)
# ISO timestamps remain strings; no incidental YAML date conversion.
SafeLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in vals if tag != "tag:yaml.org,2002:timestamp"]
    for k, vals in SafeLoader.yaml_implicit_resolvers.items()
}


def load_yaml(path: Path) -> Any:
    try:
        if path.stat().st_size > 2 * 1024**2:
            raise LiaError("config_size_limit")
        text = path.read_text(encoding="utf-8")
        nesting = 0
        for event in yaml.parse(text):
            if isinstance(event, yaml.AliasEvent):
                raise LiaError("yaml_alias_forbidden")
            if isinstance(event, (yaml.SequenceStartEvent, yaml.MappingStartEvent)):
                nesting += 1
                if nesting > 16:
                    raise LiaError("depth_limit")
            elif isinstance(event, (yaml.SequenceEndEvent, yaml.MappingEndEvent)):
                nesting -= 1
        result = yaml.load(text, Loader=SafeLoader)
        depth(result)
        return result
    except (yaml.YAMLError, UnicodeError, RecursionError, TypeError) as exc:
        raise LiaError("invalid_yaml") from exc
    except OSError as exc:
        raise LiaError("config_io_error", 4) from exc


def parse_model(cls: type[BaseModel], value: Any) -> Any:
    try:
        return cls.model_validate(value)
    except (ValidationError, ValueError) as exc:
        # Do not leak offending values from Pydantic's error representation.
        raise LiaError("invalid_" + cls.__name__.lower()) from exc


def load_config(path: Path | None) -> Config:
    return parse_model(Config, load_yaml(path)) if path else Config()


def manifest_hash(manifest: Manifest) -> str:
    value = manifest.model_dump(by_alias=True)
    value.pop("input_root")
    value["sources"] = sorted(value["sources"], key=lambda s: (s["source_id"], s["path"]))
    return digest(value)
