from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import iter_paths, link_name, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class NetworkHandler(Handler):
    name = "linux-network"
    category = "network"
    root = Path("/sys/class/net")

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        root = self.root
        if not root.is_dir():
            report.warnings.append("network sysfs topology is unavailable")
            return report
        report.evidence.append(str(root))
        for path in iter_paths(root):
            facts, evidence = read_fields(path, ("address", "addr_assign_type", "type", "mtu", "flags", "operstate", "carrier", "speed", "duplex", "ifindex", "iflink", "dev_id", "dev_port"))
            driver = link_name(path / "device" / "driver")
            if driver:
                facts["driver"] = driver
                evidence.append(str(path / "device" / "driver"))
            facts["physical_device"] = (path / "device").exists()
            report.devices.append(Device(id=path.name, name=path.name, path=str(path), facts=facts))
            report.evidence.extend(evidence)
        return report
