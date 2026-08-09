from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from hwprobe.model import ProbeLevel


class RedactionMode(str, Enum):
    NONE = "none"
    IDENTIFIERS = "identifiers"
    STRICT = "strict"


@dataclass(frozen=True, slots=True)
class ScanPolicy:
    maximum_probe_level: ProbeLevel = ProbeLevel.PASSIVE
    handler_timeout_seconds: float = 10.0
    redaction: RedactionMode = RedactionMode.IDENTIFIERS
    isolate_handlers: bool = True

    def __post_init__(self) -> None:
        if self.handler_timeout_seconds <= 0:
            raise ValueError("handler timeout must be greater than zero")

    def to_dict(self) -> dict[str, object]:
        return {
            "maximum_probe_level": int(self.maximum_probe_level),
            "handler_timeout_seconds": self.handler_timeout_seconds,
            "redaction": self.redaction.value,
            "isolate_handlers": self.isolate_handlers,
        }
