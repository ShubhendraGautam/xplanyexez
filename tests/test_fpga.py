from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hwprobe.cli import main
from hwprobe.fpga import discover_usb_debuggers, get_board_profile


def write_field(base: Path, name: str, value: str) -> None:
    (base / name).write_text(value + "\n", encoding="utf-8")


class FpgaProfileTests(unittest.TestCase):
    def test_primer_profile_has_reviewed_identity_facts(self) -> None:
        profile = get_board_profile("tang-primer-25k-dock")
        self.assertEqual(profile.fpga_part, "GW5A-LV25MG121")
        self.assertEqual(profile.expected_idcodes, ("0x0001281b",))
        self.assertEqual(profile.jtag_ir_length_bits, 8)

    def test_unknown_profile_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown FPGA board profile"):
            get_board_profile("unknown")


class FpgaDiscoveryTests(unittest.TestCase):
    def make_fixture(self, root: Path) -> None:
        hub = root / "usb1"
        hub.mkdir()
        write_field(hub, "idVendor", "1d6b")
        write_field(hub, "idProduct", "0002")

        device = root / "1-2"
        device.mkdir()
        for name, value in {
            "idVendor": "1234",
            "idProduct": "5678",
            "manufacturer": "Sipeed",
            "product": "Tang Primer 25K FPGA Partner",
            "serial": "PRIVATE-SERIAL-001",
            "bDeviceClass": "00",
            "bDeviceSubClass": "00",
            "bDeviceProtocol": "00",
            "bcdDevice": "0100",
            "busnum": "1",
            "devnum": "7",
            "speed": "480",
            "authorized": "1",
        }.items():
            write_field(device, name, value)

        interface = root / "1-2:1.0"
        interface.mkdir()
        for name, value in {
            "bInterfaceNumber": "00",
            "bAlternateSetting": "0",
            "bNumEndpoints": "2",
            "bInterfaceClass": "ff",
            "bInterfaceSubClass": "ff",
            "bInterfaceProtocol": "ff",
        }.items():
            write_field(interface, name, value)
        driver_target = root / "drivers" / "ftdi_sio"
        driver_target.mkdir(parents=True)
        (interface / "driver").symlink_to(driver_target)
        (interface / "tty").mkdir()
        (interface / "tty" / "ttyUSB0").mkdir()

    def test_discovery_reads_descriptors_but_redacts_serial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root)
            report = discover_usb_debuggers("tang-primer-25k-dock", sysfs_root=root)

        self.assertEqual(report["probe_level"], 1)
        self.assertEqual(report["transmitted_bytes"], 0)
        self.assertEqual(report["status"], "candidates-found-unverified")
        self.assertEqual(report["candidate_count"], 1)
        device = report["usb_peripherals"][0]
        self.assertEqual(device["vid_pid"], "1234:5678")
        self.assertEqual(device["profile_match"], "strong")
        self.assertFalse(device["verified_target"])
        self.assertTrue(device["serial"]["redacted"])
        self.assertNotIn("value", device["serial"])
        self.assertEqual(device["interfaces"][0]["driver"], "ftdi_sio")
        self.assertEqual(device["interfaces"][0]["tty_devices"], ["ttyUSB0"])

    def test_explicit_private_output_includes_serial(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_fixture(root)
            report = discover_usb_debuggers(
                "tang-primer-25k-dock",
                sysfs_root=root,
                include_identifiers=True,
            )
        self.assertEqual(report["usb_peripherals"][0]["serial"]["value"], "PRIVATE-SERIAL-001")

    def test_empty_usb_topology_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = discover_usb_debuggers(
                "tang-primer-25k-dock",
                sysfs_root=Path(directory),
            )
        self.assertEqual(report["status"], "no-usb-peripherals")
        self.assertEqual(report["candidate_count"], 0)


class FpgaCliTests(unittest.TestCase):
    def test_board_and_blocked_adapter_are_visible(self) -> None:
        with patch("builtins.print") as output:
            self.assertEqual(main(["fpga", "boards"]), 0)
        self.assertIn("tang-primer-25k-dock", output.call_args.args[0])

        with patch("builtins.print") as output:
            self.assertEqual(main(["p2", "adapters"]), 0)
        line = output.call_args.args[0]
        self.assertIn("tang-primer-25k-jtag", line)
        self.assertIn("blocked-pending-device-capture", line)
        self.assertIn("no JTAG bytes are enabled", line)


if __name__ == "__main__":
    unittest.main()
