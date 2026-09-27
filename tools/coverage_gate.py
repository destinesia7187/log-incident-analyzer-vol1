import json
import sys
from pathlib import Path


def check(data):
    def branch(s):
        return 100 * s["covered_branches"] / s["num_branches"] if s["num_branches"] else 100

    failures = []
    if branch(data["totals"]) < 85:
        failures.append("package branch coverage <85%")
    for name, info in data["files"].items():
        if (
            Path(name).name in {"normalize.py", "rules.py", "detection.py", "triage.py"}
            and branch(info["summary"]) < 90
        ):
            failures.append(name + ": branch coverage <90%")
    return failures


if __name__ == "__main__":
    failures = check(
        json.loads(Path(sys.argv[1] if len(sys.argv) > 1 else "reports/coverage.json").read_text())
    )
    print("\n".join(failures) if failures else "Coverage gates passed")
    raise SystemExit(bool(failures))
