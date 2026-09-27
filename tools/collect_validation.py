"""Collect final, observed validation evidence; preserve incomplete acceptance."""

import json
import platform
import shutil
from pathlib import Path

from check_traceability import check

from lia.common import digest, sha_file, write_json

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
DEST = ROOT / "docs" / "validation"


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def main():
    DEST.mkdir(parents=True, exist_ok=True)
    outcomes = {}
    for name in ["test-outcomes-functional-final.json", "test-outcomes-acceptance-final.json"]:
        for item in read(REPORTS / name):
            outcomes[item["nodeid"]] = item
    combined = sorted(outcomes.values(), key=lambda item: item["nodeid"])
    write_json(DEST / "test-outcomes-combined.json", combined)
    trace = check(read(ROOT / "docs" / "test-cases.json"), combined)
    write_json(DEST / "traceability.json", trace)
    copies = {
        "coverage-final.json": "coverage.json",
        "test-outcomes-functional-final.json": "test-outcomes-312.json",
        "test-outcomes-313-final.json": "test-outcomes-313.json",
        "test-outcomes-acceptance-final.json": "test-outcomes-acceptance.json",
        "mutations.json": "mutations.json",
        "dependency-audit.json": "dependency-audit.json",
        "sbom.cyclonedx.json": "sbom.cyclonedx.json",
        "runtime-sbom.cyclonedx.json": "runtime-sbom.cyclonedx.json",
        "secret-scan.json": "secret-scan.json",
        "static-checks.json": "static-checks.json",
    }
    for source, target in copies.items():
        shutil.copyfile(REPORTS / source, DEST / target)
    wheel = read(REPORTS / "wheel-smoke.json")
    if wheel["wheel_sha256"] != sha_file(ROOT / "dist" / wheel["wheel"]):
        raise ValueError("Distribution changed after clean installation smoke")
    wheel["python"] = "isolated virtual environment"
    wheel["demo"]["report"] = "demo/report.html"
    write_json(DEST / "wheel-smoke.json", wheel)
    source_hash = digest({p.name: sha_file(p) for p in (ROOT / "src" / "lia").glob("*.py")})
    performance = []
    for name in ["benchmark-100k-final", "benchmark-million-final"]:
        report = read(REPORTS / "release-benchmarks" / name / "benchmark.json")
        if report["source_hash"] != source_hash:
            raise ValueError("Benchmark source does not match the release")
        shutil.copyfile(REPORTS / "release-benchmarks" / name / "benchmark.json", DEST / (name + ".json"))
        performance.append(
            {
                "events": report["profile"]["events"],
                "warmups": report["profile"]["warmups"],
                "measured_runs": len(report["runs"]),
                "median_seconds": report["median_seconds"],
                "max_seconds": report["max_seconds"],
                "peak_rss_mib": report["peak_rss_bytes"] / 1024**2,
                "max_disk_bytes": max(r["disk_bytes"] for r in report["runs"]),
                "platform": report["platform"],
            }
        )
    write_json(
        DEST / "performance-summary.json",
        {"source_hash": source_hash, "fixed_linux_acceptance": "not run", "profiles": performance},
    )
    counts = {
        state: sum(item["outcome"] == state for item in combined) for state in ["passed", "failed", "skipped"]
    }
    summary = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "source_hash": source_hash,
        "combined_test_outcomes": counts,
        "python313_passed": sum(
            r["outcome"] == "passed" for r in read(REPORTS / "test-outcomes-313-final.json")
        ),
        "catalog": trace,
        "full_v1_acceptance": False,
        "open_gates": ["Linux CI matrix", "Docker SEC-020", "fixed Linux PERF-001/PERF-002"],
        "performance": performance,
    }
    write_json(DEST / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
