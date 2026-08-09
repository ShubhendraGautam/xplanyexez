from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import link_name, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class GraphicsHandler(Handler):
    name = "linux-drm"
    category = "graphics"

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        root = Path("/sys/class/drm")
        if not root.is_dir():
            report.warnings.append("DRM sysfs topology is unavailable")
            return report
        report.evidence.append(str(root))
        for path in sorted(root.iterdir()):
            facts, evidence = read_fields(path, ("enabled", "status", "modes", "dpms"))
            driver = link_name(path / "device" / "driver")
            if driver:
                facts["driver"] = driver
                evidence.append(str(path / "device" / "driver"))
            report.devices.append(Device(id=path.name, name=path.name, path=str(path), facts=facts))
            report.evidence.extend(evidence)
        return report
