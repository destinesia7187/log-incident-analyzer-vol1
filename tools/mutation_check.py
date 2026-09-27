"""Run six targeted mutations against isolated source copies, never the checkout."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = [
    (
        "threshold",
        "detection.py",
        'len(state.events) >= aggregate["threshold"]["gte"]',
        'len(state.events) > aggregate["threshold"]["gte"]',
        "tests/test_detectors.py::test_det001",
    ),
    (
        "tenant_key",
        "detection.py",
        'key = tuple(event.get(f) for f in aggregate["group_by"])',
        'key = tuple(event.get(f) for f in aggregate["group_by"] if f != "tenant.id")',
        "tests/test_detectors.py::test_det004",
    ),
    (
        "left_boundary",
        "detection.py",
        "while state.events and state.events[0].time <= event.time - window:",
        "while state.events and state.events[0].time < event.time - window:",
        "tests/test_time.py::test_boundaries",
    ),
    (
        "redaction",
        "normalize.py",
        "fields = {k: v for k, v in fields.items() if v is not None}",
        'fields = {k: v for k, v in fields.items() if v is not None}\n    fields["leaked_raw"] = raw',
        "tests/test_security_storage.py::test_secret_outputs",
    ),
    (
        "html_escape",
        "reporting.py",
        "Environment(autoescape=True, undefined=StrictUndefined)",
        "Environment(autoescape=False, undefined=StrictUndefined)",
        "tests/test_security_storage.py::test_html_escape",
    ),
    (
        "sequence_order",
        "detection.py",
        "before.interval[1] < after.interval[0]",
        "True",
        "tests/test_time.py::test_order_not_invented",
    ),
]


def main():
    records = []
    parent = ROOT / "reports" / "mutation-work"
    parent.mkdir(parents=True, exist_ok=True)
    for name, filename, before, after, test in MUTATIONS:
        with tempfile.TemporaryDirectory(prefix=name + "-", dir=parent) as tmp:
            sandbox = Path(tmp)
            src = sandbox / "src"
            shutil.copytree(ROOT / "src" / "lia", src / "lia", ignore=shutil.ignore_patterns("__pycache__"))
            target = src / "lia" / filename
            text = target.read_text(encoding="utf-8")
            if before not in text:
                raise RuntimeError("Mutation anchor changed: " + name)
            if name == "sequence_order":
                # Disable both order checks so the temporal-order regression must kill the mutant.
                text = text.replace("or candidate_upper >= event.interval[0]", "or False")
            target.write_text(text.replace(before, after, 1), encoding="utf-8")
            env = os.environ.copy()
            env["PYTHONPATH"] = str(src)
            env["PYTHONDONTWRITEBYTECODE"] = "1"
            result = subprocess.run(
                [sys.executable, "-m", "pytest", "-q", test, "--basetemp", str(sandbox / "tmp")],
                cwd=ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=120,
            )
            records.append(
                {
                    "name": name,
                    "killed": result.returncode == 1 and "failed" in result.stdout,
                    "exit_code": result.returncode,
                    "test": test,
                }
            )
            print(
                name + ": " + ("killed" if records[-1]["killed"] else "SURVIVED / infrastructure error"),
                flush=True,
            )
    report = {"mutations": records, "passed": all(r["killed"] for r in records)}
    (ROOT / "reports" / "mutations.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
