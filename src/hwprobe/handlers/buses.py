from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import link_name
from hwprobe.model import Device, HandlerReport, ProbeLevel


class BusTopologyHandler(Handler):
    """Coverage net: enumerate every Linux bus without blindly reading attributes."""

    name = "linux-bus-topology"
    category = "bus-topology"
    default_probe_level = ProbeLevel.TOPOLOGY
    supported_probe_levels = (ProbeLevel.TOPOLOGY,)

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.TOPOLOGY)
        root = Path("/sys/bus")
        if not root.is_dir():
            report.warnings.append("Linux bus topology is unavailable")
            return report
        report.evidence.append(str(root))
        counts: dict[str, int] = {}
        for bus in sorted(root.iterdir()):
            devices = bus / "devices"
            if not devices.is_dir():
                continue
            try:
                entries = sorted(devices.iterdir())
            except PermissionError:
                report.warnings.append(f"cannot enumerate bus {bus.name}")
                continue
            counts[bus.name] = len(entries)
            report.evidence.append(str(devices))
            for path in entries:
                driver = link_name(path / "driver")
                facts = {"bus": bus.name}
                if driver:
                    facts["driver"] = driver
                report.devices.append(Device(id=f"{bus.name}:{path.name}", name=path.name, path=str(path), facts=facts))
        report.facts["device_count_by_bus"] = counts
        return report
