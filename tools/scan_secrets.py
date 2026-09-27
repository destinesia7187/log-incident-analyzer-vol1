"""Small offline credential-pattern check; complements, not replaces, manual review."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    ".git",
    ".venv",
    "reports",
    "dist",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    "__pycache__",
    ".lia",
}
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b"),
}


def main():
    findings = []
    scanned = 0
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED or part.startswith(".pytest-tmp") for part in relative.parts):
            continue
        if not path.is_file() or path.suffix not in {
            ".py",
            ".md",
            ".json",
            ".jsonl",
            ".yml",
            ".yaml",
            ".toml",
            ".txt",
            ".cjs",
        }:
            continue
        text = path.read_text(encoding="utf-8")
        scanned += 1
        for name, pattern in PATTERNS.items():
            for match in pattern.finditer(text):
                findings.append(
                    {
                        "file": relative.as_posix(),
                        "line": text.count("\n", 0, match.start()) + 1,
                        "kind": name,
                    }
                )
    report = {
        "passed": not findings,
        "scanned_files": scanned,
        "patterns": list(PATTERNS),
        "findings": findings,
        "scope": "Common structured token patterns only; not a comprehensive secret detector",
    }
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "secret-scan.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report))
    return bool(findings)


if __name__ == "__main__":
    raise SystemExit(main())
