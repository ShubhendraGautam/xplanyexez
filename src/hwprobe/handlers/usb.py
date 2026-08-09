from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import iter_paths, link_name, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class UsbHandler(Handler):
    name = "linux-usb"
    category = "usb"
    root = Path("/sys/bus/usb/devices")

    _fields = ("idVendor", "idProduct", "manufacturer", "product", "serial", "bDeviceClass", "bDeviceSubClass", "bDeviceProtocol", "bcdDevice", "speed", "busnum", "devnum", "version", "maxchild", "authorized")

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        root = self.root
        if not root.is_dir():
            report.warnings.append("USB sysfs topology is unavailable")
            return report
        report.evidence.append(str(root))
        for path in iter_paths(root):
            facts, evidence = read_fields(path, self._fields)
            if "idVendor" not in facts and "bDeviceClass" not in facts:
                continue
            driver = link_name(path / "driver")
            if driver:
                facts["driver"] = driver
                evidence.append(str(path / "driver"))
            display = facts.get("product") or f"{facts.get('idVendor', '?')}:{facts.get('idProduct', '?')}"
            report.devices.append(Device(id=path.name, name=display, path=str(path), facts=facts))
            report.evidence.extend(evidence)
        return report
