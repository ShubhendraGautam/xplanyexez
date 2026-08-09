from __future__ import annotations

from abc import ABC, abstractmethod

from hwprobe.model import HandlerReport, ProbeLevel


class Handler(ABC):
    name: str
    category: str
    default_probe_level = ProbeLevel.PASSIVE
    supported_probe_levels = (ProbeLevel.TOPOLOGY, ProbeLevel.PASSIVE)
    required_privileges: tuple[str, ...] = ()
    resource_locks: tuple[str, ...] = ()
    side_effects = ("read-only operating-system interfaces",)
    known_hazards = ("collection may expose stable hardware identifiers",)
    prerequisites = ("Linux procfs/sysfs interfaces used by the handler are mounted",)
    recovery_plan = ("terminate the isolated worker; no hardware state was intentionally changed",)
    default_timeout_seconds = 10.0

    @classmethod
    def capabilities(cls) -> dict[str, object]:
        return {
            "supported_probe_levels": [int(level) for level in cls.supported_probe_levels],
            "default_probe_level": int(cls.default_probe_level),
            "required_privileges": list(cls.required_privileges),
            "resource_locks": list(cls.resource_locks),
            "side_effects": list(cls.side_effects),
            "known_hazards": list(cls.known_hazards),
            "prerequisites": list(cls.prerequisites),
            "recovery_plan": list(cls.recovery_plan),
            "default_timeout_seconds": cls.default_timeout_seconds,
        }

    @abstractmethod
    def probe(self) -> HandlerReport:
        raise NotImplementedError
