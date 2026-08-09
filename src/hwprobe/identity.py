from __future__ import annotations

import hashlib
import socket
from pathlib import Path

from hwprobe.io import read_text
from hwprobe.model import Device


def _digest(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        encoded = part.encode("utf-8", errors="surrogatepass")
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def stable_host_id() -> str:
    """Return a non-reversible host-scoped ID without exposing machine-id."""
    for path in (Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")):
        value = read_text(path, limit=4096)
        if value:
            return f"host-sha256:{_digest('xplanyexez-host-v1', value)}"
    return f"host-sha256:{_digest('xplanyexez-host-v1', socket.gethostname())}"


def assign_stable_id(device: Device, *, host_id: str, handler: str, category: str) -> None:
    """Assign a host-scoped, best-effort identity that is stable across boots."""
    device.stable_id = f"device-sha256:{_digest('xplanyexez-device-v1', host_id, handler, category, device.id)}"
