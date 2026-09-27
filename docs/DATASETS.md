# Datasets and evaluation

## Collections

| Collection | Contents | Use |
|---|---|---|
| development | 48 authored scenarios: 16 suspicious, 16 benign, 16 degraded | Development and contract regression |
| evaluation | 120 historical synthetic scenarios, shared generator with development | Historical comparison only; not independent evaluation |
| evaluation-v2 | 40 attack + 80 benign episodes, separately authored behavior templates | Current frozen evaluation |
| lab | Six captured HTTP workflows: three suspicious, three benign | Instrumentation and end-to-end validation |

All identities, sessions and addresses are synthetic. The lab binds only `127.0.0.1` and uses a small purpose-built audit application. Captures come from actual HTTP requests; the application is not a production IdP or a realistic network adversary environment.

## Reproduce

```sh
uv run lia replay --suite datasets/development/manifest.yml --output reports/development
uv run lia replay --suite datasets/evaluation-v2/manifest.yml --output reports/evaluation-v2
uv run python tools/report_evaluation.py --run reports/evaluation-v2 --suite datasets/evaluation-v2/manifest.yml
uv run python tools/capture_lab.py --output reports/lab
uv run python tools/compare_variants.py --output reports/ablation
```

Dataset generation scripts refuse to overwrite frozen versions. `freeze.json` pins the suite hash; scenario metadata pins input/manifest hashes. Detection reads only event files and source metadata; labels, intended outcomes and prohibited conclusions live in the separate suite manifest.

## What the metrics mean

Primary alerts must match tenant/application, detector family, entity, interval and relevant event evidence. Matching is one-to-one, ordered by shared evidence count, temporal proximity and stable IDs. Duplicate detections count against primary precision. Auxiliary detector hits are reported separately; they do not substitute for a missing required chain.

v2 results: **TP 40, FP 4, FN 0, TN 76**; primary precision **90.91%**, eligible and end-to-end recall **100%**, F1 **95.24%**. Wilson 95% intervals: precision **78.84–96.41%**, recall **91.24–100%**. Per-family recall has only five attack examples, with an interval of **56.55–100%**. Four intentionally benign episodes meet the same observable rule conditions as attacks.

Across all detectors there are 89 alerts and 63 cases (29.21% fewer review items). The benign scenarios produce 34 alerts including auxiliary rules across 1,692 events, or 200.95 alerts per 10,000 benign events. That value is an alert rate, not FPR and not the primary FP count. These distinctions matter: the headline primary precision does not describe every alert a SOC would see.

v2 contains no degraded attacks; the development and property suites exercise missing data separately. Its perfect eligible recall therefore says little about partially instrumented production systems. Templates were frozen before v2 replay, but were authored by the implementation's author with knowledge of the rule contract. An external blind dataset is still needed to establish generalization.

## Context comparison

The A/B/C experiment keeps the same recovery input and a separately authored approval record:

| Variant | Alerts | Review items | Escalations | Case score |
|---|---:|---:|---:|---:|
| A — separate rules | 3 | 3 | 2 | n/a |
| B — assembled cases | 3 | 1 | 1 | 75 |
| C — cases + approval + telemetry | 3 | 1 | 1 | 55 |

The MFA chain remains visible and still recommends escalation. Case reduction is not a reduction in detector false positives. Analyst time has not been measured.
