from __future__ import annotations

import os
import platform
from pathlib import Path

from hwprobe.cpuid import CpuidUnavailable, NativeCpuidTransport
from hwprobe.handlers.base import Handler
from hwprobe.io import iter_paths, read_fields, read_text
from hwprobe.model import Device, HandlerReport, ProbeLevel


class CpuHandler(Handler):
    name = "linux-cpu"
    category = "cpu"
    side_effects = (
        "read-only operating-system interfaces",
        "temporary worker CPU-affinity changes",
        "architectural CPUID instruction queries on x86-64",
    )
    known_hazards = (
        "collection may expose stable hardware identifiers",
        "a hypervisor may filter or synthesize CPUID responses",
    )
    prerequisites = (
        "Linux procfs/sysfs interfaces used by the handler are mounted",
        "native x86 CPUID requires x86-64 and executable anonymous memory",
    )
    cpuinfo_path = Path("/proc/cpuinfo")
    sys_cpu_root = Path("/sys/devices/system/cpu")
    cpuid_transport_type = NativeCpuidTransport

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        cpuinfo_path = self.cpuinfo_path
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
        if not records:
            report.warnings.append("/proc/cpuinfo contained no decodable processor records")
        report.facts["logical_cpu_count"] = len(records) or os.cpu_count()
        report.facts["kernel_online_cpu_count"] = os.cpu_count()
        sys_cpu = self.sys_cpu_root
        fields, evidence = read_fields(sys_cpu, ("online", "offline", "possible", "present", "isolated"))
        report.facts.update(fields)
        report.evidence.extend(evidence)
        used_cpu_ids: set[str] = set()
        for index, record in enumerate(records):
            reported_cpu_id = record.get("processor", str(index))
            cpu_id = reported_cpu_id
            if not cpu_id.isdecimal() or cpu_id in used_cpu_ids:
                cpu_id = str(index)
                report.warnings.append(
                    f"invalid or duplicate processor id {reported_cpu_id!r}; using record index {cpu_id}"
                )
            used_cpu_ids.add(cpu_id)
            topology, paths = read_fields(
                sys_cpu / f"cpu{cpu_id}" / "topology",
                ("physical_package_id", "die_id", "core_id", "cluster_id", "core_cpus_list", "thread_siblings_list"),
            )
            facts = dict(record)
            if topology:
                facts["topology"] = topology
            report.evidence.extend(paths)
            report.devices.append(Device(id=f"cpu{cpu_id}", name=record.get("model name") or record.get("Processor"), path=str(sys_cpu / f"cpu{cpu_id}"), facts=facts))
        self._capture_cpuid(report)
        vulnerabilities = sys_cpu / "vulnerabilities"
        vulnerability_facts: dict[str, str] = {}
        if vulnerabilities.is_dir():
            for path in iter_paths(vulnerabilities):
                value = read_text(path)
                if value is not None:
                    vulnerability_facts[path.name] = value
                    report.evidence.append(str(path))
        if vulnerability_facts:
            report.facts["vulnerabilities"] = vulnerability_facts
        return report

    def _capture_cpuid(self, report: HandlerReport) -> None:
        machine = platform.machine().lower()
        if machine not in {"x86_64", "amd64"}:
            report.facts["cpuid"] = {
                "status": "not_applicable",
                "architecture": machine or "unknown",
            }
            return
        transport_type = type(self).cpuid_transport_type
        if transport_type is None:
            return
        try:
            transport = transport_type()
        except CpuidUnavailable as exc:
            report.facts["cpuid"] = {"status": "unavailable", "reason": str(exc)}
            report.warnings.append(f"native CPUID unavailable: {exc}")
            return

        captured = 0
        unavailable: list[str] = []
        for device in report.devices:
            cpu_text = device.id.removeprefix("cpu")
            if not cpu_text.isdecimal():
                continue
            try:
                capture = transport.capture(int(cpu_text))
            except CpuidUnavailable as exc:
                unavailable.append(device.id)
                report.warnings.append(f"{device.id} CPUID unavailable: {exc}")
                continue
            device.facts["cpuid"] = {
                **capture.decoded,
                "raw": [record.to_dict() for record in capture.records],
            }
            report.evidence.extend(capture.evidence)
            report.warnings.extend(f"{device.id} CPUID: {message}" for message in capture.truncations)
            captured += 1
        report.facts["cpuid"] = {
            "status": "complete" if captured == len(report.devices) else "partial",
            "transport": "x86-cpuid",
            "scope": "per-logical-cpu",
            "captured_cpu_count": captured,
            "unavailable_cpu_ids": unavailable,
        }
