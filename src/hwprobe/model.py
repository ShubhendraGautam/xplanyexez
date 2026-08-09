from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from typing import Any


class ProbeLevel(IntEnum):
    TOPOLOGY = 0
    PASSIVE = 1
    ACTIVE = 2
    STATEFUL = 3
    DESTRUCTIVE = 4


class HandlerStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    BLOCKED_BY_POLICY = "blocked_by_policy"


@dataclass(slots=True)
class Device:
    id: str
    name: str | None = None
    path: str | None = None
    facts: dict[str, Any] = field(default_factory=dict)
    stable_id: str | None = None
    identity_scope: str = "host"
    identity_stability: str = "best-effort"


@dataclass(slots=True)
class HandlerReport:
    handler: str
    category: str
    probe_level: int
    devices: list[Device] = field(default_factory=list)
    facts: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_ms: float = 0.0
    status: str = HandlerStatus.COMPLETE.value
    coverage: dict[str, Any] = field(default_factory=dict)
    capabilities: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
