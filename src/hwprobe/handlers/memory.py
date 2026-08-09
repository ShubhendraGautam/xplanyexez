from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import read_fields, read_text
from hwprobe.model import Device, HandlerReport, ProbeLevel


class MemoryHandler(Handler):
    name = "linux-memory"
    category = "memory"

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        meminfo_path = Path("/proc/meminfo")
        raw = read_text(meminfo_path)
        if raw is not None:
            report.facts["meminfo"] = {key.strip(): value.strip() for line in raw.splitlines() if (parts := line.partition(":"))[1] for key, value in [(parts[0], parts[2])]}
            report.evidence.append(str(meminfo_path))
        root = Path("/sys/devices/system/memory")
        if not root.is_dir():
            report.warnings.append("memory-block sysfs topology is unavailable")
            return report
        fields, evidence = read_fields(root, ("block_size_bytes", "auto_online_blocks", "crash_hotplug"))
        report.facts.update(fields)
        report.evidence.extend(evidence)
        for path in sorted(root.glob("memory[0-9]*")):
            facts, paths = read_fields(path, ("state", "online", "phys_device", "phys_index", "removable", "valid_zones"))
            report.devices.append(Device(id=path.name, name="physical memory block", path=str(path), facts=facts))
            report.evidence.extend(paths)
        return report
