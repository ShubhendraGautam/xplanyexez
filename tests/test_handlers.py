from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hwprobe.handlers.block import BlockHandler
from hwprobe.handlers.buses import BusTopologyHandler
from hwprobe.handlers.cpu import CpuHandler
from hwprobe.handlers.firmware import FirmwareHandler
from hwprobe.handlers.graphics import GraphicsHandler
from hwprobe.handlers.memory import MemoryHandler
from hwprobe.handlers.network import NetworkHandler
from hwprobe.handlers.pci import PciHandler
from hwprobe.handlers.usb import UsbHandler


def write(root: Path, relative: str, value: str | bytes) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(value, bytes):
        path.write_bytes(value)
    else:
        path.write_text(value, encoding="utf-8")
    return path


def fixture_handler(base: type, **paths: Path):
    return type(f"Fixture{base.__name__}", (base,), paths)


class PassiveHandlerFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cpu_handler(self) -> None:
        cpuinfo = write(
            self.root,
            "proc/cpuinfo",
            "processor : 0\nmodel name : Fixture CPU\nflags : one two\n\n"
            "processor : 1\nmodel name : Fixture CPU\nflags : one two\n",
        )
        sys_cpu = self.root / "sys/cpu"
        write(sys_cpu, "online", "0-1\n")
        write(sys_cpu, "cpu0/topology/core_id", "0\n")
        write(sys_cpu, "cpu1/topology/core_id", "0\n")
        write(sys_cpu, "vulnerabilities/example", "Mitigation: fixture\n")
        handler_type = fixture_handler(CpuHandler, cpuinfo_path=cpuinfo, sys_cpu_root=sys_cpu)
        report = handler_type().probe()
        self.assertEqual(len(report.devices), 2)
        self.assertEqual(report.devices[0].name, "Fixture CPU")
        self.assertEqual(report.facts["vulnerabilities"]["example"], "Mitigation: fixture")

    def test_memory_handler(self) -> None:
        meminfo = write(self.root, "proc/meminfo", "MemTotal: 1024 kB\nMemFree: 512 kB\n")
        memory = self.root / "sys/memory"
        write(memory, "block_size_bytes", "10000000\n")
        write(memory, "memory0/state", "online\n")
        handler_type = fixture_handler(MemoryHandler, meminfo_path=meminfo, root=memory)
        report = handler_type().probe()
        self.assertEqual(report.facts["meminfo"]["MemTotal"], "1024 kB")
        self.assertEqual(report.devices[0].facts["state"], "online")

    def test_pci_handler(self) -> None:
        pci = self.root / "sys/pci"
        device = pci / "0000:00:01.0"
        write(device, "vendor", "0x1234\n")
        write(device, "device", "0xabcd\n")
        driver = self.root / "drivers/fixture-pci"
        driver.mkdir(parents=True)
        (device / "driver").symlink_to(driver, target_is_directory=True)
        handler_type = fixture_handler(PciHandler, root=pci)
        report = handler_type().probe()
        self.assertEqual(report.devices[0].name, "0x1234:0xabcd")
        self.assertEqual(report.devices[0].facts["driver"], "fixture-pci")

    def test_usb_handler(self) -> None:
        usb = self.root / "sys/usb"
        device = usb / "1-1"
        write(device, "idVendor", "1234\n")
        write(device, "idProduct", "abcd\n")
        write(device, "product", "Fixture USB\n")
        handler_type = fixture_handler(UsbHandler, root=usb)
        report = handler_type().probe()
        self.assertEqual(len(report.devices), 1)
        self.assertEqual(report.devices[0].name, "Fixture USB")

    def test_block_handler(self) -> None:
        block = self.root / "sys/block"
        device = block / "sda"
        write(device, "size", "2048\n")
        write(device, "device/model", "Fixture Disk\n")
        write(device, "queue/logical_block_size", "512\n")
        handler_type = fixture_handler(BlockHandler, root=block)
        report = handler_type().probe()
        self.assertEqual(report.devices[0].name, "Fixture Disk")
        self.assertEqual(report.devices[0].facts["queue"]["logical_block_size"], "512")

    def test_network_handler(self) -> None:
        network = self.root / "sys/net"
        device = network / "eth0"
        write(device, "address", "00:11:22:33:44:55\n")
        write(device, "operstate", "up\n")
        (device / "device").mkdir(parents=True)
        handler_type = fixture_handler(NetworkHandler, root=network)
        report = handler_type().probe()
        self.assertEqual(report.devices[0].facts["operstate"], "up")
        self.assertTrue(report.devices[0].facts["physical_device"])

    def test_graphics_handler(self) -> None:
        drm = self.root / "sys/drm"
        connector = drm / "card0-HDMI-A-1"
        write(connector, "status", "connected\n")
        write(connector, "modes", "1920x1080\n")
        handler_type = fixture_handler(GraphicsHandler, root=drm)
        report = handler_type().probe()
        self.assertEqual(report.devices[0].facts["status"], "connected")

    def test_firmware_handler(self) -> None:
        dmi = self.root / "sys/dmi"
        acpi = self.root / "sys/acpi"
        efi = self.root / "sys/efi"
        write(dmi, "product_name", "Fixture Board\n")
        table = write(acpi, "DSDT", b"fixture-acpi")
        write(efi, "FixtureVar-00000000-0000-0000-0000-000000000000", b"value")
        handler_type = fixture_handler(FirmwareHandler, dmi_root=dmi, acpi_root=acpi, efi_root=efi)
        report = handler_type().probe()
        self.assertEqual(report.devices[0].name, "Fixture Board")
        self.assertEqual(report.facts["acpi_tables"]["DSDT"]["size"], table.stat().st_size)
        self.assertEqual(report.facts["efi_variable_count"], 1)

    def test_bus_topology_handler(self) -> None:
        buses = self.root / "sys/bus"
        (buses / "pci/devices/0000:00:01.0").mkdir(parents=True)
        (buses / "usb/devices/1-1").mkdir(parents=True)
        handler_type = fixture_handler(BusTopologyHandler, root=buses)
        report = handler_type().probe()
        self.assertEqual(report.facts["device_count_by_bus"], {"pci": 1, "usb": 1})
        self.assertEqual(len(report.devices), 2)

    def test_all_handlers_report_unavailable_primary_roots(self) -> None:
        missing = self.root / "missing"
        handler_types = (
            fixture_handler(CpuHandler, cpuinfo_path=missing, sys_cpu_root=missing),
            fixture_handler(MemoryHandler, meminfo_path=missing, root=missing),
            fixture_handler(PciHandler, root=missing),
            fixture_handler(UsbHandler, root=missing),
            fixture_handler(BlockHandler, root=missing),
            fixture_handler(NetworkHandler, root=missing),
            fixture_handler(GraphicsHandler, root=missing),
            fixture_handler(FirmwareHandler, dmi_root=missing, acpi_root=missing, efi_root=missing),
            fixture_handler(BusTopologyHandler, root=missing),
        )
        for handler_type in handler_types:
            with self.subTest(handler=handler_type.name):
                report = handler_type().probe()
                self.assertTrue(report.warnings)
                self.assertEqual(report.devices, [])

    def test_cpu_and_memory_malformed_text_is_reported(self) -> None:
        malformed = write(self.root, "malformed", "not a key value record\n\ufffd\n")
        empty_root = self.root / "empty"
        empty_root.mkdir()
        cpu_type = fixture_handler(CpuHandler, cpuinfo_path=malformed, sys_cpu_root=empty_root)
        memory_type = fixture_handler(MemoryHandler, meminfo_path=malformed, root=empty_root)
        cpu_report = cpu_type().probe()
        memory_report = memory_type().probe()
        self.assertTrue(any("no decodable" in warning for warning in cpu_report.warnings))
        self.assertTrue(any("no decodable" in warning for warning in memory_report.warnings))

    def test_cpu_invalid_and_duplicate_ids_cannot_escape_topology_root(self) -> None:
        cpuinfo = write(
            self.root,
            "cpuinfo-invalid-ids",
            "processor : ../../outside\nmodel name : First\n\n"
            "processor : ../../outside\nmodel name : Second\n",
        )
        sys_cpu = self.root / "sys/cpu"
        sys_cpu.mkdir(parents=True)
        handler_type = fixture_handler(CpuHandler, cpuinfo_path=cpuinfo, sys_cpu_root=sys_cpu)
        report = handler_type().probe()
        self.assertEqual([device.id for device in report.devices], ["cpu0", "cpu1"])
        self.assertTrue(all(Path(device.path).is_relative_to(sys_cpu) for device in report.devices))
        self.assertEqual(len(report.warnings), 2)


if __name__ == "__main__":
    unittest.main()
