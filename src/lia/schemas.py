"""Versioned public result schemas."""

BASE = {"$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object"}
ARRAY = {"type": "array", "items": {"type": "object"}}
STRING = {"type": "string"}
STRINGS = {"type": "array", "items": STRING, "uniqueItems": True}
INTEGER = {"type": "integer"}


def record(required, properties):
    return {"type": "object", "required": required, "properties": properties}


ALERT = record(
    [
        "id",
        "rule_id",
        "rule_version",
        "tenant_id",
        "application_id",
        "start",
        "end",
        "evidence_ids",
        "severity",
        "attack",
        "confidence",
    ],
    {
        "id": {"type": "string", "pattern": "^ALT-"},
        "rule_id": STRING,
        "rule_version": {"type": "integer", "minimum": 1},
        "start": INTEGER,
        "end": INTEGER,
        "evidence_ids": {**STRINGS, "minItems": 1},
        "tenant_id": STRING,
        "application_id": STRING,
        "severity": {"enum": ["low", "medium", "high"]},
        "confidence": {"enum": ["supported", "limited"]},
        "attack": ARRAY,
    },
)
CASE = record(
    [
        "id",
        "alert_ids",
        "evidence_ids",
        "status",
        "score",
        "score_components",
        "priority",
        "decision",
        "facts",
        "hypotheses",
        "alternatives",
        "next_steps",
        "history",
        "notes",
        "edges",
    ],
    {
        "id": {"type": "string", "pattern": "^CASE-"},
        "alert_ids": {**STRINGS, "minItems": 1},
        "evidence_ids": {**STRINGS, "minItems": 1},
        "status": {"enum": ["new", "in_review", "escalated", "closed"]},
        "score": {"type": "integer", "minimum": 0, "maximum": 100},
        "score_components": {
            "type": "array",
            "minItems": 1,
            "items": record(["reason", "value"], {"reason": STRING, "value": INTEGER}),
        },
        "priority": {"enum": ["low", "medium", "high", "critical"]},
        "decision": {"enum": ["review", "escalate"]},
        "facts": ARRAY,
        "hypotheses": STRINGS,
        "alternatives": STRINGS,
        "next_steps": STRINGS,
        "history": ARRAY,
        "notes": ARRAY,
        "edges": ARRAY,
    },
)
EVIDENCE = record(
    [
        "uid",
        "time",
        "fields",
        "source_id",
        "artifact",
        "line",
        "record_digest",
        "precision_us",
        "uncertainty_us",
        "flags",
    ],
    {
        "uid": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        "time": INTEGER,
        "fields": record(
            ["event.action", "event.outcome", "tenant.id", "app.id"],
            {k: STRING for k in ["event.action", "event.outcome", "tenant.id", "app.id"]},
        ),
        "source_id": STRING,
        "artifact": STRING,
        "line": {"type": "integer", "minimum": 1},
        "record_digest": STRING,
        "precision_us": {"type": "integer", "minimum": 1},
        "uncertainty_us": {"type": "integer", "minimum": 0},
        "flags": STRINGS,
    },
)
QUALITY = record(
    ["rule_id", "status", "candidates", "eligible", "excluded", "missing_fields"],
    {
        "rule_id": STRING,
        "status": {"enum": ["ready", "degraded", "unavailable", "no_data"]},
        **{k: {"type": "integer", "minimum": 0} for k in ["candidates", "eligible", "excluded"]},
        "missing_fields": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}},
    },
)
SCHEMAS = {
    "analysis.json": {
        **BASE,
        "required": [
            "schema_version",
            "program_version",
            "dataset_hash",
            "rules_hash",
            "config_hash",
            "event_count",
            "alerts",
            "cases",
            "evidence",
            "quality",
            "quality_findings",
        ],
        "properties": {
            "schema_version": {"const": "1.0"},
            "event_count": {"type": "integer", "minimum": 0},
            "dataset_hash": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "alerts": {"type": "array", "items": ALERT},
            "cases": {"type": "array", "items": CASE},
            "evidence": {"type": "array", "items": EVIDENCE},
            "quality": {"type": "array", "items": QUALITY},
            "quality_findings": ARRAY,
        },
    },
    "run.json": {
        **BASE,
        "required": ["schema_version", "state", "program_version", "exit_code"],
        "properties": {
            "schema_version": {"const": "1.0"},
            "state": {
                "enum": [
                    "created",
                    "ingesting",
                    "analyzing",
                    "completed",
                    "completed_with_warnings",
                    "failed",
                    "interrupted",
                ]
            },
            "exit_code": {"enum": [0, 2, 3, 4, 10, 130]},
        },
    },
    "quality.json": {
        **BASE,
        "required": ["schema_version", "rules", "findings"],
        "properties": {
            "schema_version": {"const": "1.0"},
            "rules": {"type": "array", "items": QUALITY},
            "findings": ARRAY,
        },
    },
}
