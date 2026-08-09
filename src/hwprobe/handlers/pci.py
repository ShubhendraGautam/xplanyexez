from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import iter_paths, link_name, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class PciHandler(Handler):
    name = "linux-pci"
    category = "pci"
    root = Path("/sys/bus/pci/devices")

    _fields = ("vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision", "irq", "numa_node", "enable", "power_state", "dma_mask_bits", "consistent_dma_mask_bits")

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        root = self.root
        if not root.is_dir():
            report.warnings.append("PCI sysfs topology is unavailable")
            return report
        report.evidence.append(str(root))
        for path in iter_paths(root):
            facts, evidence = read_fields(path, self._fields)
            driver = link_name(path / "driver")
            iommu_group = link_name(path / "iommu_group")
            if driver:
                facts["driver"] = driver
                evidence.append(str(path / "driver"))
            if iommu_group:
                facts["iommu_group"] = iommu_group
                evidence.append(str(path / "iommu_group"))
            report.devices.append(Device(id=path.name, name=f"{facts.get('vendor', '?')}:{facts.get('device', '?')}", path=str(path), facts=facts))
            report.evidence.extend(evidence)
        return report
