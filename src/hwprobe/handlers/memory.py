from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import iter_paths, read_fields, read_text
from hwprobe.model import Device, HandlerReport, ProbeLevel


class MemoryHandler(Handler):
    name = "linux-memory"
    category = "memory"
    meminfo_path = Path("/proc/meminfo")
    root = Path("/sys/devices/system/memory")

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        meminfo_path = self.meminfo_path
        raw = read_text(meminfo_path)
        if raw is not None:
            meminfo = {
                key.strip(): value.strip()
                for line in raw.splitlines()
                if (parts := line.partition(":"))[1]
                for key, value in [(parts[0], parts[2])]
            }
            report.facts["meminfo"] = meminfo
            report.evidence.append(str(meminfo_path))
            if not meminfo:
                report.warnings.append("/proc/meminfo contained no decodable fields")
        else:
            report.warnings.append("could not read /proc/meminfo")
        root = self.root
        if not root.is_dir():
            report.warnings.append("memory-block sysfs topology is unavailable")
            return report
        fields, evidence = read_fields(root, ("block_size_bytes", "auto_online_blocks", "crash_hotplug"))
        report.facts.update(fields)
        report.evidence.extend(evidence)
        for path in (entry for entry in iter_paths(root) if entry.name.startswith("memory") and entry.name[6:].isdigit()):
            facts, paths = read_fields(path, ("state", "online", "phys_device", "phys_index", "removable", "valid_zones"))
            report.devices.append(Device(id=path.name, name="physical memory block", path=str(path), facts=facts))
            report.evidence.extend(paths)
        return report
