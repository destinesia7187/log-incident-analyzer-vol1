"""Build a reviewable source bundle without environments, secrets or working databases."""

import argparse
import hashlib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP = {"src", "tests", "tools", "schemas", "datasets", "docs", "examples", "benchmarks", ".github"}
FILES = {
    "START_HERE_RU.md",
    "README.md",
    "SECURITY.md",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "pyproject.toml",
    "uv.lock",
    "requirements.lock.txt",
    "Dockerfile",
    ".dockerignore",
    ".gitignore",
    ".gitattributes",
}


def package(output: Path):
    if output.exists():
        raise ValueError("Choose a new release archive path")
    candidates = [ROOT / name for name in FILES]
    for name in TOP:
        candidates.extend((ROOT / name).rglob("*"))
    candidates.extend((ROOT / "dist").glob("*.whl"))
    candidates.extend((ROOT / "dist").glob("*.tar.gz"))
    included = []
    for item in candidates:
        rel = item.relative_to(ROOT)
        if not item.is_file() or any(p.startswith(".lia") or p == "__pycache__" for p in rel.parts):
            continue
        if (
            any(p.startswith(".review") for p in rel.parts)
            or item.suffix in {".key", ".pyc"}
            or ".sqlite" in item.name
        ):
            continue
        if item.is_symlink() or not item.resolve().is_relative_to(ROOT.resolve()):
            raise ValueError("Unsafe release path: " + str(rel))
        included.append((item, rel))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for item, rel in sorted(included, key=lambda x: str(x[1])):
            archive.write(item, "log-incident-analyzer/" + rel.as_posix())
    with zipfile.ZipFile(output, "r") as archive:
        if archive.testzip() is not None:
            raise ValueError("Archive integrity check failed")
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(".sha256").write_text(checksum + "  " + output.name + "\n")
    print(f"{len(included)} files; {output.stat().st_size} bytes; SHA-256 {checksum}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package(args.output)
