from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import link_name, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class PciHandler(Handler):
    name = "linux-pci"
    category = "pci"

    _fields = ("vendor", "device", "subsystem_vendor", "subsystem_device", "class", "revision", "irq", "numa_node", "enable", "power_state", "dma_mask_bits", "consistent_dma_mask_bits")

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        root = Path("/sys/bus/pci/devices")
        if not root.is_dir():
            report.warnings.append("PCI sysfs topology is unavailable")
            return report
        report.evidence.append(str(root))
        for path in sorted(root.iterdir()):
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
