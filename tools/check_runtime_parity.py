"""Compare deterministic analysis hashes across two installed Python runtimes."""

import argparse
import json
import subprocess
import sys
from pathlib import Path

from lia.common import write_json

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--python-other", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Choose a fresh output directory")
    runs = []
    for index, python in enumerate([sys.executable, args.python_other]):
        target = args.output / f"runtime-{index}"
        subprocess.run(
            [python, "-m", "lia.cli", "demo", "--output", str(target)],
            check=True,
            capture_output=True,
            text=True,
        )
        metadata = json.loads((target / "run.json").read_text())
        runs.append({"python": metadata["python"], "analysis_hash": metadata["analysis_hash"]})
    result = {
        "runs": runs,
        "passed": runs[0]["analysis_hash"] == runs[1]["analysis_hash"],
        "key_scope": "Both runs share the same private workspace key",
    }
    write_json(args.output / "parity.json", result)
    print(json.dumps(result))
    raise SystemExit(0 if result["passed"] else 1)
