# Architecture and contracts

```text
manifest + local files
  → bounded reader / quarantine accounting
  → allowlisted normalization / UTC / identity / provenance
  → SQLite deduplication and event-time ordering
  → validated rule predicates and bounded aggregate windows
  → alerts with evidence / cases with rationale and priority
  → JSON + Markdown + static escaped HTML
```

Runtime dependencies are deliberately few: Typer, Pydantic, PyYAML, Jinja2 and timezone data. SQLite is part of Python. Evaluation and benchmarking are separate entry points and do not influence detection.

## Module boundaries

| Module | Responsibility |
|---|---|
| `config`, `common` | Strict configuration, safe paths, bounded parsing, canonical hashes |
| `normalize` | Source contract, identity, IP trust, timestamps, allowlisted fields |
| `ingest`, `storage` | Streaming input, quarantine counts, provenance, deduplication, SQLite |
| `rules`, `detection` | DSL validation, three-valued predicates, aggregate windows and sequences |
| `triage` | Case grouping, evidence links, contextual priority |
| `pipeline` | Workspace lock, staged publication, review operations |
| `reporting`, `schemas` | Escaped reports and public result schemas |
| `evaluation`, `benchmark` | Label-separated replay, metrics and measured workloads |
| `cli` | Command contracts and stable error codes |

## Event identity and provenance

An original event ID is namespaced by tenant, application and source. Exact duplicates add provenance without another event. Conflicting contents under one identity invalidate that identity for detection. Events without an original ID use source/artifact/line identity; equal-looking web requests are not silently merged.

Each normalized record contains source ID, artifact SHA-256, line, byte offset and record digest. Original secret-bearing JSON is never copied into the database. Missing optional fields remain absent (`Event.get()` returns `None`). Reports refer to stable event UIDs and full evidence is stored once.

## Time

Microseconds since Unix epoch are integers. Count windows are `(t-W, t]`; precisely on the left boundary is excluded. A sequence requires the upper bound of prior evidence to be strictly less than the lower bound of the later event. Stable UID sorting of tied timestamps does not establish sequence order. Excessive uncertainty excludes the event from affected rules; smaller uncertainty remains visible in confidence.

Overlapping threshold hits merge into an alert episode. The episode lasts at most one hour; a new qualifying episode is then created. DET-003 refers to a qualifying failure window, not arbitrary earlier failures. DET-006 requires the same session and a self-enrollment actor/target match.

## Rule authoring

Copy a packaged rule from `src/lia/resources/rules` into a dedicated directory, then run `lia validate-rules --rules path/to/rules`. A custom rule directory replaces the packaged set. Sequence dependencies must be present and acyclic.

Required metadata includes ID/version/title/status, owner, description/rationale, references, test IDs, severity, required capabilities/fields, false positives and next checks. Known ATT&CK identifiers are constrained by a reviewed allowlist.

Predicates: `all`, `any`, `not`, `equals`, `in`, `exists`, `cidr_match`, `starts_with`. Only documented fields are accepted. Missing values propagate as unknown, including under `not`. Unknown operators, regex, executable expressions, arbitrary SQL, YAML aliases, duplicate keys and unknown fields are rejected.

Aggregates: `event_count`, `distinct_count`, `multi_count`, `sequence`. Duration syntax: positive integer plus `s`, `m` or `h`, bounded to 24 hours. Required tenant/application identity boundaries cannot be removed. Use positive, negative, exact-threshold, tenant-isolation, missing-field, boundary-time and duplicate tests for every new rule.

The implementation evaluates a validated AST in Python; SQLite provides persistence and ordering. It does not translate rules into generated SQL. This is an explicit simplification of the suggested specification architecture.

## Resource boundaries

Default limits: 256 KiB per line, 100 files, 2 GiB decompressed input, gzip expansion ratio 100 after a 10 MiB grace allowance, 100,000 active aggregate groups and 16 GiB output workspace. YAML is at most 2 MiB and depth 16. Limits are configurable and fail explicitly.

Input is streamed to SQLite. Detection traverses sorted records; active windows retain eligible events. Output volume scales with matched evidence. Limits are defensive bounds, not a guarantee that every hostile workload fits the standard benchmark memory target.
