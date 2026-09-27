# Architecture decisions

## ADR-001 — Local batch analysis and SQLite

Accepted. Analyze completed exports on one workstation. SQLite removes a server dependency, enforces evidence foreign keys and sorts by event time. Staged run directories separate partial work from published results. The tradeoff is one writer and no live ingestion or cross-host coordination.

## ADR-002 — Small declarative DSL

Accepted. Validate a bounded predicate/aggregate AST and evaluate it in Python. The language is `lia-rule/v1`; Sigma parsing/translation is deliberately outside the supported contract. This keeps missing-value and sequence behavior testable. Users supply data, never SQL or executable Python.

## ADR-003 — Event time and uncertainty

Accepted. Use UTC integer microseconds, `(t-W, t]` count windows and uncertainty intervals for strict sequences. Reject ambiguous local time. Arrival order only affects provenance, not analytic order. This can withhold a sequence when timestamps are too coarse; that limitation is safer and more informative than an invented ordering.

## ADR-004 — Identity belongs to the source namespace

Accepted. Deduplicate stable original IDs within tenant/application/source; invalidate conflicting IDs. Preserve independent observations and all provenance. Source-only detections do not inherit an arbitrary user from the last matching event. Shared addresses alone cannot unify different users.

## ADR-005 — Evidence without raw secrets

Accepted. Persist a field allowlist, HMAC raw sessions with a workspace key, remove query strings and omit raw records from error messages. A public export pseudonymizes structured identities and drops analyst notes and SQLite. Keep the key outside deliverables. Free-text review is still necessary before publishing unfamiliar production data.

## ADR-006 — Explainable triage

Accepted. Use rule severity plus documented context components, not an opaque probability. Merge alerts by bounded identity/time or explicit sequence evidence. Record facts independently of analyst hypotheses. Scoped and expiring suppressions retain evidence; a suspicious MFA registration stays visible.

## ADR-007 — Evaluate contracts and detection utility separately

Accepted. Unit/property tests check implementation semantics. Frozen evaluation supplies separately authored intent labels; those labels never enter the engine. Publish denominators, false positives and Wilson confidence intervals. Preserve v1 synthetic evaluation as historical evidence of its shared generator; use independent v2 behavior templates and separate HTTP lab captures for the current report. These remain controlled datasets and cannot establish field accuracy.
