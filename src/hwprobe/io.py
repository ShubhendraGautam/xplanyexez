from __future__ import annotations

import hashlib
import os
from dataclasses import asdict, dataclass
from pathlib import Path


MAX_TEXT_BYTES = 1024 * 1024


@dataclass(slots=True)
class IoAudit:
    attempted_reads: int = 0
    successful_reads: int = 0
    not_found: int = 0
    permission_denied: int = 0
    io_errors: int = 0
    size_limit_exceeded: int = 0

    def to_dict(self) -> dict[str, int]:
        return asdict(self)


_audit: IoAudit | None = None


def begin_io_audit() -> None:
    global _audit
    _audit = IoAudit()


def finish_io_audit() -> dict[str, int]:
    global _audit
    result = (_audit or IoAudit()).to_dict()
    _audit = None
    return result


def _record(field: str) -> None:
    if _audit is not None:
        setattr(_audit, field, getattr(_audit, field) + 1)


def read_text(path: Path, *, limit: int = MAX_TEXT_BYTES) -> str | None:
    """Read a small virtual/system file without following unbounded content."""
    _record("attempted_reads")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            data = os.read(fd, limit + 1)
        finally:
            os.close(fd)
    except FileNotFoundError:
        _record("not_found")
        return None
    except PermissionError:
        _record("permission_denied")
        return None
    except OSError:
        _record("io_errors")
        return None
    if len(data) > limit:
        _record("size_limit_exceeded")
        return None
    _record("successful_reads")
    return data.decode("utf-8", errors="replace").strip()


def read_fields(base: Path, names: tuple[str, ...]) -> tuple[dict[str, str], list[str]]:
    facts: dict[str, str] = {}
    evidence: list[str] = []
    for name in names:
        path = base / name
        value = read_text(path)
        if value is not None:
            facts[name] = value
            evidence.append(str(path))
    return facts, evidence


def link_name(path: Path) -> str | None:
    try:
        return path.resolve(strict=True).name
    except (FileNotFoundError, PermissionError, OSError):
        return None


def describe_binary(path: Path, *, hash_limit: int = 16 * 1024 * 1024) -> dict[str, object] | None:
    """Return metadata and a digest for bounded firmware blobs without exposing bytes."""
    _record("attempted_reads")
    try:
        size = path.stat().st_size
        if size > hash_limit:
            _record("size_limit_exceeded")
            return {"size": size, "sha256": None, "note": "digest size limit exceeded"}
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while chunk := stream.read(64 * 1024):
                digest.update(chunk)
        _record("successful_reads")
        return {"size": size, "sha256": digest.hexdigest()}
    except FileNotFoundError:
        _record("not_found")
        return None
    except PermissionError:
        _record("permission_denied")
        return None
    except OSError:
        _record("io_errors")
        return None
