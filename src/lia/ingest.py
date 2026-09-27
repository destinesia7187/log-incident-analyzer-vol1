"""Bounded local file ingestion including a single gzip member."""

from __future__ import annotations

import hashlib
import re
import zlib
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from .common import LiaError, json_load, safe_file, sha_file
from .config import Config, Manifest
from .normalize import normalize
from .storage import Store

COMBINED = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "([^"\r\n]*)" (\d{3}) (\S+) "[^"\r\n]*" "[^"\r\n]*"$')


def parse_combined(text: str) -> dict:
    m = COMBINED.fullmatch(text)
    if not m:
        raise LiaError("invalid_combined")
    try:
        stamp = datetime.strptime(m[2], "%d/%b/%Y:%H:%M:%S %z").isoformat()
        method, uri, _ = m[3].split(" ", 2)
    except ValueError as exc:
        raise LiaError("invalid_combined") from exc
    return {
        "timestamp": stamp,
        "network": {"peer_ip": m[1]},
        "http": {"method": method, "path": uri, "status": int(m[4])},
    }


def chunks(path: Path, config: Config, totals: dict) -> Iterator[bytes]:
    compressed = path.suffix.lower() == ".gz"
    if path.suffix.lower() in {".zip", ".tar", ".7z", ".bz2"}:
        raise LiaError("unsupported_archive")
    decompressor = zlib.decompressobj(31) if compressed else None
    unpacked = 0
    consumed = 0

    def account(block: bytes) -> bytes:
        nonlocal unpacked
        unpacked += len(block)
        totals["input_bytes"] += len(block)
        if totals["input_bytes"] > config.limits.input_bytes:
            raise LiaError("input_size_limit", 4)
        if (
            compressed
            and unpacked > config.limits.gzip_grace_bytes
            and unpacked > max(1, consumed) * config.limits.gzip_ratio
        ):
            raise LiaError("gzip_ratio_limit", 4)
        return block

    try:
        with path.open("rb") as stream:
            while block := stream.read(65536):
                consumed += len(block)
                if decompressor is None:
                    yield account(block)
                    continue
                if decompressor.eof:
                    raise LiaError("multiple_gzip_members", 4)
                pending = block
                while pending:
                    result = decompressor.decompress(pending, 65536)
                    pending = decompressor.unconsumed_tail
                    if decompressor.unused_data:
                        raise LiaError("multiple_gzip_members", 4)
                    if result:
                        yield account(result)
                if decompressor.eof:
                    continue
        if decompressor and not decompressor.eof:
            raise LiaError("truncated_gzip", 4)
    except (OSError, zlib.error) as exc:
        raise LiaError("input_read_error", 4) from exc


def lines(path: Path, config: Config, totals: dict) -> Iterator[tuple[int, int, bytes | None, str]]:
    """Retain at most one bounded line; hash overlong records incrementally."""
    number, offset, record_start = 1, 0, 0
    pending = bytearray()
    hasher = hashlib.sha256()
    oversize = False
    had_bytes = False
    for block in chunks(path, config, totals):
        pieces = block.split(b"\n")
        for i, piece in enumerate(pieces):
            hasher.update(piece)
            had_bytes |= bool(piece)
            if not oversize:
                pending.extend(piece)
                if len(pending) > config.limits.line_bytes:
                    oversize = True
                    pending.clear()
            offset += len(piece)
            if i < len(pieces) - 1:
                yield (
                    number,
                    record_start,
                    None if oversize else bytes(pending).removesuffix(b"\r"),
                    hasher.hexdigest(),
                )
                offset += 1
                number += 1
                record_start = offset
                pending.clear()
                oversize, had_bytes = False, False
                hasher = hashlib.sha256()
    if had_bytes:
        yield (
            number,
            record_start,
            None if oversize else bytes(pending).removesuffix(b"\r"),
            hasher.hexdigest(),
        )


def ingest(
    store: Store, manifest: Manifest, manifest_path: Path, config: Config, key: bytes
) -> tuple[dict, list[dict], list[dict]]:
    if len(manifest.sources) > config.limits.max_files:
        raise LiaError("file_count_limit")
    root = (manifest_path.parent / manifest.input_root).absolute()
    counts = dict.fromkeys(
        [
            "rows_seen",
            "accepted_unique",
            "duplicate_rows",
            "quarantined_rows",
            "conflicted_rows",
            "blank_rows",
            "input_bytes",
            "reused_artifacts",
            "unknown_field_rows",
        ],
        0,
    )
    findings: list[dict] = []
    artifacts: list[dict] = []
    seen: dict[str, tuple[str, str, str]] = {}
    duplicates_by_uid: dict[str, int] = {}
    for source in sorted(manifest.sources, key=lambda s: (s.source_id, s.path)):
        path = safe_file(root, source.path)
        initial_stat = path.stat()
        file_hash = sha_file(path)
        scope = (source.source_id, source.tenant_id, source.application_id)
        if file_hash in seen:
            if seen[file_hash] != scope:
                raise LiaError("artifact_scope_conflict")
            counts["reused_artifacts"] += 1
            continue
        seen[file_hash] = scope
        artifacts.append({"sha256": file_hash, "source_id": source.source_id, "size": initial_stat.st_size})
        store.db.execute(
            "INSERT OR IGNORE INTO artifacts VALUES(?,?,?)",
            (file_hash, source.source_id, initial_stat.st_size),
        )
        for number, offset, raw, record_hash in lines(path, config, counts):
            counts["rows_seen"] += 1
            metadata = {
                "source_id": source.source_id,
                "line": number,
                "artifact": file_hash,
                "digest": record_hash,
            }
            try:
                if raw is None:
                    raise LiaError("line_too_large")
                if number == 1:
                    raw = raw.removeprefix(b"\xef\xbb\xbf")
                if not raw:
                    counts["blank_rows"] += 1
                    continue
                text = raw.decode("utf-8", errors="strict")
                data = parse_combined(text) if source.format == "nginx-combined-v1" else json_load(text)
                event = normalize(data, source, config, key, file_hash, number, offset, record_hash)
                state, old_count = store.add(event)
                counts[state] += 1
                if state == "duplicate_rows":
                    duplicates_by_uid[event.uid] = duplicates_by_uid.get(event.uid, 0) + 1
                if old_count:
                    prior_duplicates = duplicates_by_uid.pop(event.uid, 0)
                    counts["accepted_unique"] -= 1
                    counts["duplicate_rows"] -= prior_duplicates
                    counts["conflicted_rows"] += 1 + prior_duplicates
                if state == "conflicted_rows":
                    findings.append({**metadata, "code": "event_id_conflict"})
                if any(f.startswith("unknown_fields") for f in event.flags):
                    counts["unknown_field_rows"] += 1
            except (LiaError, UnicodeError) as exc:
                if isinstance(exc, LiaError) and exc.exit_code == 4:
                    raise
                counts["quarantined_rows"] += 1
                findings.append(
                    {**metadata, "code": exc.code if isinstance(exc, LiaError) else "invalid_utf8"}
                )
            if counts["rows_seen"] % 10000 == 0:
                store.db.commit()
                if (
                    sum(p.stat().st_size for p in store.path.parent.glob("analysis.sqlite*"))
                    > config.limits.workspace_bytes
                ):
                    raise LiaError("workspace_size_limit", 4)
        final_stat = path.stat()
        if (
            initial_stat.st_size != final_stat.st_size
            or initial_stat.st_mtime_ns != final_stat.st_mtime_ns
            or sha_file(path) != file_hash
        ):
            raise LiaError("input_changed", 4)
        store.db.commit()
    # Potential copies across non-identical web artifacts cannot be safely collapsed.
    store.index()
    repeated = []
    if len(artifacts) > 1:
        repeated = store.db.execute("""SELECT p.record_digest,COUNT(DISTINCT p.artifact) FROM event_provenance p
            JOIN events e ON e.uid=p.uid WHERE e.action='http.request' GROUP BY p.record_digest HAVING COUNT(DISTINCT p.artifact)>1 LIMIT 100""").fetchall()
    if repeated:
        findings.append({"code": "possible_duplicate_web_records", "distinct_patterns": len(repeated)})
    return counts, findings, sorted(artifacts, key=lambda a: a["sha256"])
