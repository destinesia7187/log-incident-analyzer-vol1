# Validation and acceptance status

Measured locally on **2026-09-27**, Windows 11 build 26200, Python 3.12.14 / 3.13.15. This document distinguishes executed checks from workflow definitions and specification gates that still require another environment.

## Executed checks

| Check | Result | Evidence |
|---|---|---|
| Combined Python 3.12 checks, including recorded performance and delivery | **326 passed, 0 failed, 2 skipped** across the functional and acceptance runs | `validation/test-outcomes-combined.json` |
| Python 3.12 functional/security/delivery checks | 324 passed; Docker test skipped; dedicated performance checks separate | `validation/test-outcomes-312.json` |
| Python 3.13 functional/security checks | **322 passed** | `validation/test-outcomes-313.json` |
| Cross-runtime deterministic analysis | Identical analysis hashes with a shared workspace key | `validation/parity.json` |
| Package branch coverage | **90.79%**, target ≥85% | `validation/coverage.json` |
| Normalization/time branch coverage | **98.57%**, target ≥90% | same |
| Rule DSL branch coverage | **100%**, target ≥90% | same |
| Detection branch coverage | **94.92%**, target ≥90% | same |
| Triage branch coverage | **94.83%**, target ≥90% | same |
| Targeted mutations | **6/6 killed** | `validation/mutations.json` |
| Development replay | **48/48 passed** | Frozen `datasets/development` |
| Independent v2 evaluation replay | **120/120 contract expectations passed** | `validation/evaluation-summary.json` |
| Captured HTTP lab workflows | **6/6 passed** | `../datasets/lab/lab-report.json` |
| Clean wheel install outside source checkout | Passed with hashed runtime dependencies | `validation/wheel-smoke.json` |
| Ruff lint/format and mypy | Passed | Reproduction commands below |
| Dependency audit | No known vulnerabilities reported at check time | `validation/dependency-audit.json` |
| SBOM | CycloneDX JSON, including the checked development environment | `validation/sbom.cyclonedx.json` |
| Common credential-pattern scan | Passed; limited pattern set, not a general secrecy guarantee | `validation/secret-scan.json` |
| Browser report smoke | Edge 154.0.4258.37; 1280px / 390px, no external requests, script errors or document overflow | `validation/browser-smoke.json`, screenshots |

Property checks use Hypothesis with bounded generated examples. The mutation suite deliberately changes the threshold comparison, tenant grouping, window boundary, secret-field filtering, HTML escaping and sequence ordering. Each change must cause a meaningful behavioral assertion to fail.

The original catalog has **256 case IDs**, all linked to executable tests. **253 IDs passed locally**; PERF-001, PERF-002 and SEC-020 remain unaccepted because their tests require unavailable environments. `validation/traceability.json` records the mapping. A linked test is evidence of its assertions, not automatic proof of every clause of a broad specification requirement. Cross-platform and fixed-runner requirements remain open as stated below.

## Performance

Standard workload: approximately 625 bytes per input row, 1% deliberately malformed rows, 1% failed logins and a low alert/evidence rate. One warmup precedes five measured runs. Timing covers ingest, normalization, SQLite, detection, case assembly and JSON/Markdown export. Input generation is excluded. Peak RSS is sampled every 10 ms; disk size is the completed run, while configured workspace limits also inspect the active database/WAL.

Host: 12 logical CPUs, 16,891,633,664 bytes physical memory, Windows 11. OS cache, desktop background load and local verification activity were not isolated. These are development measurements, **not acceptance results for the required fixed Linux 4 vCPU / 8 GiB / SSD host**. Per-run timings and source hashes are preserved in the attached benchmark JSON files. The maximum is reported alongside the median; slow runs are not silently removed.

Final measurements are summarized in `validation/performance-summary.json`:

| Input rows | Median | Slowest measured run | Peak RSS | Maximum completed run size |
|---|---:|---:|---:|---:|
| 100,000 | **16.27 s** | 34.50 s | 325.5 MiB | 249,793,802 bytes |
| 1,000,000 | **271.51 s** | 279.88 s | 505.5 MiB | 2,649,728,994 bytes |

**The million-event run did not reach 180 seconds on this Windows host.** No claim is made that the fixed Linux time requirement is met. Memory, disk and record-reconciliation checks passed for both profiles. Every measured million-row run accepted 990,000 unique events and quarantined the 10,000 deliberately corrupt records; no rows disappeared from accounting. Malformed input intentionally causes analysis exit code 3 inside the benchmark.

## Open acceptance gates

1. **Linux runtime matrix and Docker smoke have not been executed locally.** Docker and an installed Linux/WSL environment were unavailable. GitHub Actions defines these jobs; no hosted CI run is claimed.
2. **NFR-001 fixed-host absolute-time acceptance is unverified.** PERF-001/PERF-002 intentionally skip unless `LIA_FIXED_RUNNER=linux-4vcpu-8gib-ssd` identifies the provisioned runner. Memory/disk/count checks can still run on the recorded Windows measurements.
3. **The container-specific security test SEC-020 is skipped locally.** It must run against the built image under a non-root user, read-only root and disabled network.

These gates are why the package is version **0.1.0**, not an accepted v1.0 release. The software is implemented and locally checked; full specification acceptance is not represented as complete.

## Explicit implementation choices and limits

- Rules use a validated in-memory AST over SQLite-ordered events. The suggested SQL aggregate compiler was not needed and is not implemented.
- ATT&CK support is a reviewed technique allowlist with source/rationale metadata, not an imported complete STIX catalog. OWASP guidance informs telemetry contracts; no compliance engine or percentage of ATT&CK coverage is claimed.
- The CLI has stable sanitized error codes. It does not expose the optional debug traceback interface described in the specification.
- JSON Schemas validate public result structures and input/config models; referential evidence checks are enforced by SQLite and behavioral tests, not by JSON Schema alone.
- Case review uses SQLite as commit authority and a recovery journal for interrupted report publication. Directly opening a report during a write may observe an older file; a subsequent CLI read completes pending committed publication. An orphan stage created before the journal may require manual cleanup after verifying the writer is stopped.
- The historic evaluation-v1 generator was shared with development. Current claims use separately authored v2 behavior templates. All suites and the HTTP lab are still controlled data authored within this project; external blind validation remains future work.
- The secret scan checks only common structured token/private-key patterns. Pseudonymized output and this scan do not prove that arbitrary user-provided text contains no sensitive information.

## Reproduce full local evidence

```sh
uv sync --locked --group dev
uv run ruff check src tests tools
uv run ruff format --check src tests tools
uv run mypy src
uv run python tools/mutation_check.py
uv run pytest -m "not performance and not delivery" --cov=lia --cov-report=json:reports/coverage.json
uv run python tools/coverage_gate.py reports/coverage.json
uv run lia replay --suite datasets/evaluation-v2/manifest.yml --output reports/evaluation-v2
uv run python tools/report_evaluation.py --run reports/evaluation-v2 --suite datasets/evaluation-v2/manifest.yml
uv run python tools/capture_lab.py --output reports/lab
uv build
uv run python tools/wheel_smoke.py
uv run pip-audit --skip-editable
uv run python tools/scan_secrets.py
```

For delivery/performance tests set `LIA_CLEAN_PYTHON` to the freshly installed wheel interpreter and `LIA_BENCHMARK_DIR` to the directory containing `benchmark-100k-final/benchmark.json` and `benchmark-million-final/benchmark.json`. Enable `LIA_TEST_DOCKER=1` only with an available Docker engine and a built `lia:test` image. Never mark the fixed Linux runner variable merely to bypass a skip on another machine.

`tools/check_traceability.py` returns nonzero when required cases are missing, skipped or failing. Preserve that result for incomplete acceptance; do not turn unavailable checks into passes.
