from __future__ import annotations

import hashlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hwprobe.io import IoAudit


class EvidenceError(ValueError):
    pass


@dataclass(slots=True)
class StoreStats:
    objects_seen: int = 0
    objects_written: int = 0
    bytes_written: int = 0

    def to_dict(self) -> dict[str, int | str]:
        return {
            "algorithm": "sha256",
            "objects_seen": self.objects_seen,
            "objects_written": self.objects_written,
            "bytes_written": self.bytes_written,
        }


class ContentAddressedStore:
    """A private, deduplicated evidence store keyed by raw-content SHA-256."""

    def __init__(self, root: Path):
        self.root = root
        self.stats = StoreStats()

    def object_path(self, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise EvidenceError(f"invalid sha256 digest: {digest!r}")
        return self.root / "objects" / "sha256" / digest[:2] / digest

    def put(self, digest: str, data: bytes) -> None:
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise EvidenceError(f"artifact digest mismatch: expected {digest}, got {actual}")
        self.stats.objects_seen += 1
        target = self.object_path(digest)
        if target.exists():
            self.read_verified(digest)
            return
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{digest}.", dir=target.parent)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, target)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
        self.stats.objects_written += 1
        self.stats.bytes_written += len(data)

    def put_audit(self, audit: IoAudit) -> None:
        for digest, data in audit.artifacts.items():
            self.put(digest, data)

    def read_verified(self, digest: str) -> bytes:
        path = self.object_path(digest)
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise EvidenceError(f"cannot read evidence object {digest}: {exc}") from exc
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise EvidenceError(f"corrupt evidence object {digest}: got {actual}")
        return data


def referenced_digests(document: dict[str, Any]) -> set[str]:
    digests: set[str] = set()
    for report in document.get("reports", []):
        for observation in report.get("provenance", []):
            digest = observation.get("sha256")
            if digest:
                digests.add(digest)
    return digests


def verify_evidence(document: dict[str, Any], store: ContentAddressedStore) -> dict[str, int]:
    expected_sizes: dict[str, int] = {}
    for report in document.get("reports", []):
        for observation in report.get("provenance", []):
            digest = observation.get("sha256")
            if not digest:
                continue
            size = observation.get("size")
            if not isinstance(size, int):
                raise EvidenceError(f"evidence observation {digest} has no valid size")
            previous = expected_sizes.setdefault(digest, size)
            if previous != size:
                raise EvidenceError(f"evidence object {digest} has conflicting declared sizes")
    total_bytes = 0
    for digest, expected_size in sorted(expected_sizes.items()):
        data = store.read_verified(digest)
        if len(data) != expected_size:
            raise EvidenceError(
                f"evidence object {digest} size mismatch: expected {expected_size}, got {len(data)}"
            )
        total_bytes += len(data)
    return {"objects_verified": len(expected_sizes), "bytes_verified": total_bytes}


def write_private_manifest(document: dict[str, Any], store: ContentAddressedStore) -> Path:
    """Persist an unredacted run manifest with owner-only permissions."""
    run_id = document["run"]["run_id"]
    directory = store.root / "runs"
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / f"{run_id}.json"
    rendered = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{run_id}.", dir=directory)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(rendered)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_name, target)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
    return target
