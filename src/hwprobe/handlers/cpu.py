from __future__ import annotations

import os
from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import read_fields, read_text
from hwprobe.model import Device, HandlerReport, ProbeLevel


class CpuHandler(Handler):
    name = "linux-cpu"
    category = "cpu"

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        cpuinfo_path = Path("/proc/cpuinfo")
        raw = read_text(cpuinfo_path)
        if raw is None:
            report.warnings.append("could not read /proc/cpuinfo")
            return report
        report.evidence.append(str(cpuinfo_path))
        records = []
        for section in raw.split("\n\n"):
            record: dict[str, str] = {}
            for line in section.splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    record[key.strip()] = value.strip()
            if record:
                records.append(record)
        report.facts["logical_cpu_count"] = len(records) or os.cpu_count()
        report.facts["kernel_online_cpu_count"] = os.cpu_count()
        sys_cpu = Path("/sys/devices/system/cpu")
        fields, evidence = read_fields(sys_cpu, ("online", "offline", "possible", "present", "isolated"))
        report.facts.update(fields)
        report.evidence.extend(evidence)
        for index, record in enumerate(records):
            cpu_id = record.get("processor", str(index))
            topology, paths = read_fields(
                sys_cpu / f"cpu{cpu_id}" / "topology",
                ("physical_package_id", "die_id", "core_id", "cluster_id", "core_cpus_list", "thread_siblings_list"),
            )
            facts = dict(record)
            if topology:
                facts["topology"] = topology
            report.evidence.extend(paths)
            report.devices.append(Device(id=f"cpu{cpu_id}", name=record.get("model name") or record.get("Processor"), path=str(sys_cpu / f"cpu{cpu_id}"), facts=facts))
        vulnerabilities = sys_cpu / "vulnerabilities"
        vulnerability_facts: dict[str, str] = {}
        if vulnerabilities.is_dir():
            for path in sorted(vulnerabilities.iterdir()):
                value = read_text(path)
                if value is not None:
                    vulnerability_facts[path.name] = value
                    report.evidence.append(str(path))
        if vulnerability_facts:
            report.facts["vulnerabilities"] = vulnerability_facts
        return report
