"""Compare the specification catalog with pytest's observed case outcomes."""

import argparse
import json
from pathlib import Path


def check(catalog, outcomes):
    expected = {c["id"] for c in catalog["cases"]}
    found = {cid for item in outcomes for cid in item["case_ids"]}
    return {
        "expected": len(expected),
        "implemented": len(expected & found),
        "missing": sorted(expected - found),
        "unknown": sorted(found - expected),
        "not_passed": sorted(
            {cid for item in outcomes if item["outcome"] != "passed" for cid in item["case_ids"]}
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog", default="docs/test-cases.json")
    parser.add_argument("--results", default="reports/test-outcomes.json")
    args = parser.parse_args()
    result = check(
        json.loads(Path(args.catalog).read_text(encoding="utf-8")),
        json.loads(Path(args.results).read_text(encoding="utf-8")),
    )
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(result["missing"] or result["unknown"] or result["not_passed"]))
