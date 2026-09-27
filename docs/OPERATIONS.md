# Operations

## Input

A manifest defines a local `input_root` and explicitly lists sources. Paths are relative to that root. Each source supplies a stable ID, tenant, application, format and authority. Source IDs may repeat for rotated files only when source metadata agrees.

`app-audit-v1` fields: `schema_version`, `event_id` (optional), ISO `timestamp`, `action`, `outcome`, and optional objects `actor`, `target`, `network`, `auth`, `http`. Unknown fields are dropped, so adding an unrecognized field does not grant it meaning. See the committed input example. Authentication decisions require explicit audit outcomes.

`nginx-json-v1` uses the fixed nested layout in [the JSON example](../examples/input/nginx-json-v1.jsonl): `timestamp`, `network.peer_ip`, and `http.method`, `http.path`, `http.status`, optionally `http.request_id`. It is not a parser for every custom nginx `log_format`. Transform a different export into this shape before ingestion. [The combined example](../examples/input/nginx-combined-v1.log) uses the standard peer/identity/user/time/request/status/bytes/referer/user-agent fields. Access logs preserve HTTP evidence but cannot establish application login success. Source authority is an operator assertion, not a cryptographic verification.

Set `timezone` for naive timestamps; ambiguous/nonexistent local times are quarantined. `clock_offset_ms` adjusts known source drift; `clock_uncertainty_ms` expands ordering intervals. Set `precision_us` only when supported by the exporter. `rounding: unknown` prevents invented sequence order.

Forwarded addresses are used only when `forwarded_enabled: true` and the peer belongs to `trusted_proxy_cidrs`. The chain is inspected from the trusted side. A malformed chain falls back to the transport peer with a quality flag.

## Results and exit codes

| Code | Meaning |
|---|---|
| 0 | Analysis completed; inspect readiness and findings |
| 2 | Invalid invocation, manifest, configuration or rule |
| 3 | Partial import, required completeness not met, or replay expectations failed |
| 4 | I/O, workspace, resource limit or storage error |
| 10 | Alerts exist and `--fail-on-alert` was requested |
| 130 | Interrupted |

Import warnings take precedence over `--fail-on-alert`. `--require-complete` also returns 3 for any rule that is not ready. No-data detectors can make a valid small demonstration `completed_with_warnings` without making the whole input invalid.

`run.json` records versions, input/artifact hashes, config/rule hashes, counts, duration and completion state. `analysis_hash` excludes runtime timing. Session pseudonyms are stable within a workspace key, stored in `.lia/session.key` beside the run directories. Keep that key private; a new key changes session pseudonyms.

## Analyst review

Take a case ID from `analysis.json` or the report:

```sh
lia explain --run reports/demo --case CASE-REPLACE_WITH_REAL_ID --format markdown
lia case set-status --run reports/demo --case CASE-REPLACE_WITH_REAL_ID --status in_review --analyst analyst-1
lia case add-note --run reports/demo --case CASE-REPLACE_WITH_REAL_ID --text "Owner contact pending" --analyst analyst-1
lia case set-status --run reports/demo --case CASE-REPLACE_WITH_REAL_ID --status closed --analyst analyst-1 --verdict benign_activity --reason "Confirmed recovery ticket"
```

Transitions: new → in_review → escalated/closed; escalated → in_review/closed; closed → in_review. Closure requires a reason and one of `benign_activity`, `false_positive`, `confirmed_incident`, `inconclusive`. A note is analyst input and never detector evidence.

## Context

Context kinds: `critical` (+15), `approved` (−20), `suppression` (queue visibility), `nat` (alternative explanation). Base score is the highest rule severity (low 20, medium 40, high 60), plus 15 for DET-006, clamped to 0–100. Priorities: low <30, medium <60, high <80, critical ≥80. High/critical or DET-006 recommends escalation.

Every context entry requires an ID, source, author, reason, created time, validity interval, tenant and application. Approval and suppression also require a rule and user/IP scope; wildcards are rejected. Context applies only when its validity interval covers the entire alert. Suppression does not delete evidence or hide DET-006.

## Files and recovery

Analysis writes to a private staging directory and publishes it by directory rename. Failed/interrupted runs contain failure metadata, not a successful partial report. A workspace allows one writer. After an abrupt process kill a stale `.lia/writer.lock` may remain: verify the recorded PID is no longer running before removing that specific lock manually. Never remove an active writer's lock.

The database is local SQLite, schema version 1. Unsupported versions are rejected. Back up the complete run directory while no writer is active. Read-only or public share exports cannot be reviewed as private cases. Use a new run for new input; streaming resume is outside this version.

Case updates render into `.review-stage`, write a recovery journal, and commit the review in SQLite before promoting report files. A later CLI read finishes a pending committed review or discards an uncommitted stage. After an abrupt kill before the journal exists, an orphan `.review-stage` can be removed only after verifying the writer is stopped; the original case is unchanged. Direct filesystem readers should wait for a completed command before opening updated reports.

Reports and normalized databases still contain security-sensitive metadata. `--shareable` removes structured identities, notes and private SQLite, but it is pseudonymization, not proof that arbitrary free text contains no personal data. Keep raw source logs outside the public repository.

## Containers

```sh
docker build -t lia:test .
docker run --rm --network none --read-only --tmpfs /work:uid=10001,gid=10001 --tmpfs /tmp lia:test demo --output /work/demo
```

For your own input, mount it read-only and mount a separate writable output directory owned by UID 10001. The temporary demo command checks execution; tmpfs output disappears on exit.
