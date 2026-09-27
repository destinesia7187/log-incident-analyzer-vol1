"""A/B/C comparison on one fixed synthetic recovery export with a separate approval."""

import argparse
import copy
import json
from pathlib import Path

from lia.common import write_json
from lia.config import Config, parse_model
from lia.demo import recovery_context, story, write_input
from lia.pipeline import analyze
from lia.triage import assemble


def run(output: Path):
    manifest = write_input(output / "input", story("recovery"))
    write_json(output / "approval.json", recovery_context())
    baseline, metadata, _ = analyze(manifest, output / "baseline")
    alerts = baseline["alerts"]
    variants = [
        {
            "variant": "A: separate rules",
            "alerts": len(alerts),
            "review_items": len(alerts),
            "escalations": sum(a["severity"] == "high" for a in alerts),
        },
    ]
    for name, config in [
        ("B: cases", Config()),
        ("C: cases + approval + telemetry", parse_model(Config, {"context": [recovery_context()]})),
    ]:
        cases = assemble(copy.deepcopy(alerts), config)
        variants.append(
            {
                "variant": name,
                "alerts": len(alerts),
                "review_items": len(cases),
                "escalations": sum(c["decision"] == "escalate" for c in cases),
                "scores": [c["score"] for c in cases],
            }
        )
    result = {
        "dataset_hash": metadata["dataset_hash"],
        "variants": variants,
        "interpretation": "Case assembly reduces review items from 3 to 1. Approval changes score, not observed behavior. All three alerts arise from a known benign recovery in this authored example; grouping does not reduce detector false positives. Analyst time was not measured.",
    }
    write_json(output / "comparison.json", result)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output), indent=2))
