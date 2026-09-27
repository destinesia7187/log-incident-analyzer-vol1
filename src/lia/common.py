"""Small deterministic primitives shared by the pipeline."""

from __future__ import annotations

import hashlib
import json
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class LiaError(Exception):
    """A safe error: messages contain codes/metadata, never raw input."""

    def __init__(self, code: str, exit_code: int = 2):
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def utc_text(us: int) -> str:
    from datetime import timedelta

    return (datetime(1970, 1, 1, tzinfo=UTC) + timedelta(microseconds=us)).isoformat().replace("+00:00", "Z")


def now_text() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def terminal_safe(text: str) -> str:
    text = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    return "".join(c for c in text if c in "\n\t" or ord(c) >= 32 and ord(c) != 127)


def safe_file(root: Path, relative: str) -> Path:
    """Reject traversal and links at every component before resolving."""
    p = Path(relative)
    if p.is_absolute() or ".." in p.parts or relative.startswith(("\\", "//")):
        raise LiaError("unsafe_path")
    current = root.absolute()
    for ancestor in (*current.parents, current):
        if ancestor.exists() and is_link(ancestor):
            raise LiaError("unsafe_link")
    for part in p.parts:
        current /= part
        if current.exists() and is_link(current):
            raise LiaError("unsafe_link")
    resolved = current.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise LiaError("unsafe_path")
    if not resolved.is_file():
        raise LiaError("input_missing", 4)
    return resolved


def is_link(path: Path) -> bool:
    info = path.lstat()
    return path.is_symlink() or bool(
        getattr(info, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def json_load(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise LiaError("duplicate_json_key")
            result[key] = value
        return result

    def constant(_: str) -> None:
        raise LiaError("nonfinite_json")

    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as exc:
        raise LiaError("invalid_json") from exc


def depth(value: Any, level: int = 0) -> int:
    if level > 16:
        raise LiaError("depth_limit")
    if isinstance(value, dict):
        return max([level] + [depth(v, level + 1) for v in value.values()])
    if isinstance(value, list):
        return max([level] + [depth(v, level + 1) for v in value])
    return level
