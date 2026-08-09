from __future__ import annotations

import hashlib
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path


MAX_TEXT_BYTES = 1024 * 1024


@dataclass(slots=True)
class EvidenceObservation:
    sequence: int
    source: str
    transport: str
    operation: str
    status: str
    duration_us: int
    sha256: str | None = None
    size: int | None = None
    media_type: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, object | None]:
        return asdict(self)


@dataclass(slots=True)
class IoAudit:
    attempted_reads: int = 0
    successful_reads: int = 0
    not_found: int = 0
    permission_denied: int = 0
    io_errors: int = 0
    size_limit_exceeded: int = 0
    observations: list[EvidenceObservation] = field(default_factory=list)
    artifacts: dict[str, bytes] = field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        return {
            "attempted_reads": self.attempted_reads,
            "successful_reads": self.successful_reads,
            "not_found": self.not_found,
            "permission_denied": self.permission_denied,
            "io_errors": self.io_errors,
            "size_limit_exceeded": self.size_limit_exceeded,
            "observation_count": len(self.observations),
            "unique_artifact_count": len(self.artifacts),
            "artifact_bytes": sum(len(data) for data in self.artifacts.values()),
        }


_audit: IoAudit | None = None


def begin_io_audit() -> None:
    global _audit
    _audit = IoAudit()


def finish_io_audit() -> IoAudit:
    global _audit
    result = _audit or IoAudit()
    _audit = None
    return result


def _elapsed_us(started_ns: int) -> int:
    return max(0, (time.monotonic_ns() - started_ns) // 1000)


def _record_failure(
    path: Path,
    operation: str,
    status: str,
    started_ns: int,
    detail: str | None = None,
) -> None:
    if _audit is None:
        return
    _audit.attempted_reads += 1
    setattr(_audit, status, getattr(_audit, status) + 1)
    _audit.observations.append(
        EvidenceObservation(
            sequence=len(_audit.observations),
            source=str(path),
            transport="linux-vfs",
            operation=operation,
            status=status,
            duration_us=_elapsed_us(started_ns),
            detail=detail,
        )
    )


def _record_success(path: Path, operation: str, data: bytes, media_type: str, started_ns: int) -> None:
    if _audit is None:
        return
    digest = hashlib.sha256(data).hexdigest()
    _audit.attempted_reads += 1
    _audit.successful_reads += 1
    _audit.artifacts.setdefault(digest, data)
    _audit.observations.append(
        EvidenceObservation(
            sequence=len(_audit.observations),
            source=str(path),
            transport="linux-vfs",
            operation=operation,
            status="success",
            duration_us=_elapsed_us(started_ns),
            sha256=digest,
            size=len(data),
            media_type=media_type,
        )
    )


def read_text(path: Path, *, limit: int = MAX_TEXT_BYTES) -> str | None:
    """Read and audit a small virtual/system file using read-only open flags."""
    started_ns = time.monotonic_ns()
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK)
        try:
            chunks: list[bytes] = []
            remaining = limit + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)
    except FileNotFoundError:
        _record_failure(path, "read_text", "not_found", started_ns)
        return None
    except PermissionError:
        _record_failure(path, "read_text", "permission_denied", started_ns)
        return None
    except OSError as exc:
        _record_failure(path, "read_text", "io_errors", started_ns, type(exc).__name__)
        return None
    if len(data) > limit:
        _record_failure(path, "read_text", "size_limit_exceeded", started_ns, f"limit={limit}")
        return None
    _record_success(path, "read_text", data, "text/plain; charset=utf-8", started_ns)
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


def iter_paths(path: Path) -> list[Path]:
    """Enumerate and audit one directory without following its children."""
    started_ns = time.monotonic_ns()
    try:
        entries = sorted(path.iterdir())
    except FileNotFoundError:
        _record_failure(path, "list_directory", "not_found", started_ns)
        return []
    except PermissionError:
        _record_failure(path, "list_directory", "permission_denied", started_ns)
        return []
    except OSError as exc:
        _record_failure(path, "list_directory", "io_errors", started_ns, type(exc).__name__)
        return []
    listing = "\n".join(entry.name for entry in entries).encode("utf-8", errors="surrogatepass")
    _record_success(
        path,
        "list_directory",
        listing,
        "application/vnd.xplanyexez.directory-list",
        started_ns,
    )
    return entries


def link_name(path: Path) -> str | None:
    started_ns = time.monotonic_ns()
    try:
        target = os.readlink(path)
    except FileNotFoundError:
        _record_failure(path, "read_link", "not_found", started_ns)
        return None
    except PermissionError:
        _record_failure(path, "read_link", "permission_denied", started_ns)
        return None
    except OSError as exc:
        _record_failure(path, "read_link", "io_errors", started_ns, type(exc).__name__)
        return None
    _record_success(
        path,
        "read_link",
        target.encode("utf-8", errors="surrogatepass"),
        "inode/symlink",
        started_ns,
    )
    return Path(target).name


def describe_binary(path: Path, *, hash_limit: int = 16 * 1024 * 1024) -> dict[str, object] | None:
    """Capture bounded firmware bytes and return metadata rather than exposing bytes inline."""
    started_ns = time.monotonic_ns()
    try:
        size = path.stat().st_size
        if size > hash_limit:
            _record_failure(path, "read_binary", "size_limit_exceeded", started_ns, f"limit={hash_limit}")
            return {"size": size, "sha256": None, "note": "digest size limit exceeded"}
        with path.open("rb") as stream:
            data = stream.read(hash_limit + 1)
        if len(data) > hash_limit:
            _record_failure(path, "read_binary", "size_limit_exceeded", started_ns, f"limit={hash_limit}")
            return {"size": len(data), "sha256": None, "note": "digest size limit exceeded"}
        digest = hashlib.sha256(data).hexdigest()
        _record_success(path, "read_binary", data, "application/octet-stream", started_ns)
        return {"size": len(data), "sha256": digest}
    except FileNotFoundError:
        _record_failure(path, "read_binary", "not_found", started_ns)
        return None
    except PermissionError:
        _record_failure(path, "read_binary", "permission_denied", started_ns)
        return None
    except OSError as exc:
        _record_failure(path, "read_binary", "io_errors", started_ns, type(exc).__name__)
        return None
