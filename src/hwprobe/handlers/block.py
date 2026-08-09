from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import link_name, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class BlockHandler(Handler):
    name = "linux-block"
    category = "storage"

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        root = Path("/sys/class/block")
        if not root.is_dir():
            report.warnings.append("block sysfs topology is unavailable")
            return report
        report.evidence.append(str(root))
        for path in sorted(root.iterdir()):
            facts, evidence = read_fields(path, ("dev", "size", "ro", "removable", "range", "partition", "inflight"))
            device_facts, device_evidence = read_fields(path / "device", ("vendor", "model", "rev", "serial", "type", "state", "timeout"))
            queue_facts, queue_evidence = read_fields(path / "queue", ("logical_block_size", "physical_block_size", "minimum_io_size", "optimal_io_size", "rotational", "write_cache", "fua", "discard_granularity", "zoned"))
            if device_facts:
                facts["device"] = device_facts
            if queue_facts:
                facts["queue"] = queue_facts
            driver = link_name(path / "device" / "driver")
            if driver:
                facts["driver"] = driver
                evidence.append(str(path / "device" / "driver"))
            report.devices.append(Device(id=path.name, name=device_facts.get("model") or path.name, path=str(path), facts=facts))
            report.evidence.extend(evidence + device_evidence + queue_evidence)
        return report
