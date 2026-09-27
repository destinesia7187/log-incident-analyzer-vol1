"""Check local Markdown artifact links without following external URLs."""

import json
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def main():
    checked = 0
    missing = []
    files = list(ROOT.glob("*.md")) + list((ROOT / "docs").rglob("*.md"))
    for file in files:
        for target in re.findall(r"\]\(([^)]+)\)", file.read_text(encoding="utf-8")):
            target = target.strip("<>").split(' "', 1)[0]
            parsed = urlsplit(target)
            if parsed.scheme or not parsed.path:
                continue
            checked += 1
            if not (file.parent / unquote(parsed.path)).is_file():
                missing.append({"file": file.relative_to(ROOT).as_posix(), "target": target})
    result = {"local_links_checked": checked, "missing": missing, "passed": not missing}
    print(json.dumps(result))
    return bool(missing)


if __name__ == "__main__":
    raise SystemExit(main())
