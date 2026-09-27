"""Repeatable performance measurements with explicit measurement boundaries."""

from __future__ import annotations

import json
import platform
import statistics
import threading
import time
from pathlib import Path

from .common import LiaError, digest, sha_file, write_json
from .config import load_yaml
from .demo import raw_event, write_input
from .pipeline import analyze


def regression(baseline: dict, candidate: dict) -> dict:
    if any(baseline[k] != candidate[k] for k in ["dataset_sha256", "profile", "platform"]):
        raise LiaError("benchmark_not_comparable")
    ratio = candidate["median_seconds"] / baseline["median_seconds"]
    return {"ratio": ratio, "requires_review": ratio > 1.2}


def generate(directory: Path, count: int, seed: int = 42, high_cardinality: bool = False) -> Path:
    manifest = write_input(directory, [])
    with (directory / "app.jsonl").open("w", encoding="utf-8", newline="\n") as stream:
        for i in range(count):
            # 1% corrupt, 1% failed authentication, remaining ordinary successful activity.
            # Input generation is deliberately excluded from analysis timing.
            if i % 100 == 99:
                stream.write('{"synthetic_corrupt":\n')
                continue
            failing = i % 1000 < 10
            user = (
                f"user-{i}"
                if high_cardinality
                else f"user-{seed}-{i // 1000}"
                if failing or i % 1000 == 10
                else f"ordinary-{i % 1000}"
            )
            event = raw_event(
                i,
                i * 0.01,
                user=user,
                outcome="failure" if failing else "success",
                http={"request_id": "r" * 390},
            )
            stream.write(json.dumps(event, separators=(",", ":")) + "\n")
    return manifest


def run_benchmark(profile: Path, output: Path) -> dict:
    source_hash = digest({p.name: sha_file(p) for p in Path(__file__).parent.glob("*.py")})
    try:
        import psutil
    except ImportError as exc:
        raise LiaError("benchmark_requires_dev_dependencies") from exc
    params = load_yaml(profile)
    if not isinstance(params, dict) or set(params) - {
        "events",
        "runs",
        "warmups",
        "seed",
        "high_cardinality",
    }:
        raise LiaError("invalid_benchmark_profile")
    count, runs, warmups = params.get("events", 100000), params.get("runs", 5), params.get("warmups", 1)
    if any(type(x) is not int for x in [count, runs, warmups]) or count <= 0 or runs < 1 or warmups < 0:
        raise LiaError("invalid_benchmark_profile")
    if output.exists():
        raise LiaError("existing_output")
    output.mkdir(parents=True)
    manifest = generate(
        output / "input", count, params.get("seed", 42), params.get("high_cardinality", False)
    )
    input_file = manifest.parent / "app.jsonl"
    measurements = []
    proc = psutil.Process()
    for i in range(warmups + runs):
        peak = [proc.memory_info().rss]
        stop = threading.Event()

        def monitor():
            while not stop.wait(0.01):
                peak[0] = max(peak[0], proc.memory_info().rss)

        worker = threading.Thread(target=monitor, daemon=True)
        worker.start()
        begin = time.perf_counter()
        try:
            _, metadata, code = analyze(manifest, output / f"run-{i}")
        finally:
            stop.set()
            worker.join()
        elapsed = time.perf_counter() - begin
        result = {
            "seconds": elapsed,
            "peak_rss_bytes": peak[0],
            "exit_code": code,
            "counts": metadata["counts"],
            "phase_timings": metadata["phase_timings"],
            "disk_bytes": sum(p.stat().st_size for p in (output / f"run-{i}").rglob("*") if p.is_file()),
        }
        if i >= warmups:
            measurements.append(result)
        write_json(output / "progress.json", {"finished": i + 1, "total": warmups + runs, "last": result})
    report = {
        "schema_version": "1.0",
        "source_hash": source_hash,
        "profile": params,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": psutil.cpu_count(),
        "physical_memory_bytes": psutil.virtual_memory().total,
        "cache_mode": "uncontrolled_os_cache; warmup excluded",
        "measurement_boundary": "ingest, normalize, SQLite, detection, JSON/Markdown export",
        "dataset_sha256": sha_file(input_file),
        "input_bytes": input_file.stat().st_size,
        "runs": measurements,
        "median_seconds": statistics.median(r["seconds"] for r in measurements),
        "max_seconds": max(r["seconds"] for r in measurements),
        "peak_rss_bytes": max(r["peak_rss_bytes"] for r in measurements),
    }
    write_json(output / "benchmark.json", report)
    return report
