from __future__ import annotations

from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import describe_binary, iter_paths, read_fields
from hwprobe.model import Device, HandlerReport, ProbeLevel


class FirmwareHandler(Handler):
    name = "linux-firmware"
    category = "firmware"
    dmi_root = Path("/sys/class/dmi/id")
    acpi_root = Path("/sys/firmware/acpi/tables")
    efi_root = Path("/sys/firmware/efi/efivars")

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        dmi = self.dmi_root
        fields = ("bios_date", "bios_release", "bios_vendor", "bios_version", "board_asset_tag", "board_name", "board_serial", "board_vendor", "board_version", "chassis_asset_tag", "chassis_serial", "chassis_type", "chassis_vendor", "chassis_version", "product_family", "product_name", "product_serial", "product_sku", "product_uuid", "product_version", "sys_vendor")
        dmi_facts, evidence = read_fields(dmi, fields)
        if dmi_facts:
            report.devices.append(Device(id="dmi", name=dmi_facts.get("product_name"), path=str(dmi), facts=dmi_facts))
            report.evidence.extend(evidence)
        acpi = self.acpi_root
        tables: dict[str, object] = {}
        if acpi.is_dir():
            report.evidence.append(str(acpi))
            for path in iter_paths(acpi):
                if path.is_file():
                    description = describe_binary(path)
                    if description is not None:
                        tables[path.name] = description
                        report.evidence.append(str(path))
        report.facts["acpi_tables"] = tables
        efi = self.efi_root
        report.facts["efi_runtime_available"] = efi.is_dir()
        if efi.is_dir():
            try:
                report.facts["efi_variable_count"] = len(iter_paths(efi))
                report.evidence.append(str(efi))
            except PermissionError:
                report.warnings.append("EFI variables exist but cannot be enumerated")
        if not dmi_facts and not tables and not efi.is_dir():
            report.warnings.append("DMI, ACPI, and EFI firmware interfaces are unavailable")
        return report
