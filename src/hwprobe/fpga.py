from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from pathlib import Path

from hwprobe.io import link_name, read_fields


USB_SYSFS_ROOT = Path("/sys/bus/usb/devices")
_USB_DEVICE_NAME = re.compile(r"\d+-\d+(?:\.\d+)*$")
_USB_DEVICE_FIELDS = (
    "idVendor",
    "idProduct",
    "manufacturer",
    "product",
    "serial",
    "bcdDevice",
    "bDeviceClass",
    "bDeviceSubClass",
    "bDeviceProtocol",
    "busnum",
    "devnum",
    "speed",
    "authorized",
)
_USB_INTERFACE_FIELDS = (
    "bInterfaceNumber",
    "bAlternateSetting",
    "bNumEndpoints",
    "bInterfaceClass",
    "bInterfaceSubClass",
    "bInterfaceProtocol",
    "interface",
)


@dataclass(frozen=True, slots=True)
class FpgaBoardProfile:
    name: str
    display_name: str
    fpga_family: str
    fpga_part: str
    expected_idcodes: tuple[str, ...]
    jtag_ir_length_bits: int
    dock_debugger_mcu: str
    transport_hint: str
    matching_terms: tuple[str, ...]
    sources: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


BOARD_PROFILES = {
    "tang-primer-25k-dock": FpgaBoardProfile(
        name="tang-primer-25k-dock",
        display_name="Sipeed Tang Primer 25K with Dock",
        fpga_family="Gowin GW5A-25",
        fpga_part="GW5A-LV25MG121",
        expected_idcodes=("0x0001281b",),
        jtag_ir_length_bits=8,
        dock_debugger_mcu="Bouffalo Lab BL616",
        transport_hint="onboard USB-C JTAG/UART debugger; openFPGALoader board cable is ft2232",
        matching_terms=("sipeed", "tang", "primer", "25k", "fpga partner", "ft2232"),
        sources=(
            "https://github.com/sipeed/sipeed_wiki/blob/main/docs/hardware/en/tang/tang-primer-25k/primer-25k.md",
            "https://github.com/sipeed/sipeed_wiki/blob/main/docs/hardware/zh/tang/common-doc/update_debugger.md",
            "https://github.com/trabucayre/openFPGALoader/blob/master/src/board.hpp",
            "https://github.com/trabucayre/openFPGALoader/blob/master/src/gowin.cpp",
        ),
    )
}


def get_board_profile(name: str) -> FpgaBoardProfile:
    try:
        return BOARD_PROFILES[name]
    except KeyError as exc:
        available = ", ".join(sorted(BOARD_PROFILES))
        raise ValueError(f"unknown FPGA board profile {name!r}; available profiles: {available}") from exc


def _serial_value(serial: str | None, *, include_identifiers: bool) -> dict[str, object]:
    if not serial:
        return {"present": False}
    if include_identifiers:
        return {"present": True, "value": serial}
    return {
        "present": True,
        "redacted": True,
        "sha256": hashlib.sha256(serial.encode("utf-8")).hexdigest(),
    }


def _tty_names(interface_path: Path) -> list[str]:
    names: set[str] = set()
    for location in (interface_path, interface_path / "tty"):
        try:
            children = location.iterdir()
        except (FileNotFoundError, NotADirectoryError, PermissionError, OSError):
            continue
        for child in children:
            if child.name != "tty" and child.name.startswith("tty"):
                names.add(child.name)
    return sorted(names)


def _interfaces(root: Path, device_name: str) -> list[dict[str, object]]:
    interfaces: list[dict[str, object]] = []
    try:
        paths = sorted(root.glob(f"{device_name}:*"))
    except OSError:
        return interfaces
    for path in paths:
        fields, _ = read_fields(path, _USB_INTERFACE_FIELDS)
        driver = link_name(path / "driver")
        entry: dict[str, object] = {"sysfs_name": path.name, **fields}
        if driver:
            entry["driver"] = driver
        tty_names = _tty_names(path)
        if tty_names:
            entry["tty_devices"] = tty_names
        interfaces.append(entry)
    return interfaces


def _match_profile(
    profile: FpgaBoardProfile,
    fields: dict[str, str],
    interfaces: list[dict[str, object]],
) -> tuple[str, list[str]]:
    identity = " ".join(
        fields.get(name, "").lower() for name in ("manufacturer", "product")
    )
    reasons: list[str] = []
    strong_terms = [term for term in profile.matching_terms[:-1] if term in identity]
    if strong_terms:
        reasons.append("descriptor terms: " + ", ".join(strong_terms))
    drivers = {str(item.get("driver", "")).lower() for item in interfaces}
    ftdi_hint = "ft2232" in identity or "ftdi_sio" in drivers
    if ftdi_hint:
        reasons.append("FT2232/ftdi_sio transport hint")
    if "sipeed" in strong_terms and any(term in strong_terms for term in ("primer", "25k")):
        return "strong", reasons
    if len(strong_terms) >= 2:
        return "possible", reasons
    if ftdi_hint:
        return "transport-only", reasons
    return "unidentified", reasons


def discover_usb_debuggers(
    profile_name: str,
    *,
    sysfs_root: Path = USB_SYSFS_ROOT,
    include_identifiers: bool = False,
) -> dict[str, object]:
    """Inventory USB descriptors without opening an endpoint or transmitting bytes."""

    profile = get_board_profile(profile_name)
    result: dict[str, object] = {
        "schema_version": "xplanyexez-fpga-discovery/v1",
        "probe_level": 1,
        "transmitted_bytes": 0,
        "board_profile": profile.to_dict(),
        "sysfs_root": str(sysfs_root),
        "usb_peripherals": [],
        "candidate_count": 0,
        "warnings": [],
    }
    if not sysfs_root.is_dir():
        result["status"] = "usb-sysfs-unavailable"
        result["warnings"].append("Linux USB sysfs topology is unavailable")
        return result

    peripherals: list[dict[str, object]] = []
    try:
        paths = sorted(sysfs_root.iterdir())
    except OSError as exc:
        result["status"] = "usb-sysfs-unreadable"
        result["warnings"].append(f"cannot enumerate USB sysfs: {type(exc).__name__}")
        return result

    for path in paths:
        if not _USB_DEVICE_NAME.fullmatch(path.name):
            continue
        fields, _ = read_fields(path, _USB_DEVICE_FIELDS)
        vendor = fields.get("idVendor", "").lower()
        device_class = fields.get("bDeviceClass", "").lower()
        if not vendor or vendor == "1d6b" or device_class == "09":
            continue
        serial = fields.pop("serial", None)
        interfaces = _interfaces(sysfs_root, path.name)
        confidence, reasons = _match_profile(profile, fields, interfaces)
        peripherals.append({
            "sysfs_name": path.name,
            "locator": f"usb:{fields.get('busnum', '?')}:{fields.get('devnum', '?')}:{path.name}",
            "vid_pid": f"{vendor}:{fields.get('idProduct', '').lower()}",
            "descriptors": fields,
            "serial": _serial_value(serial, include_identifiers=include_identifiers),
            "interfaces": interfaces,
            "profile_match": confidence,
            "match_reasons": reasons,
            "verified_target": False,
        })

    result["usb_peripherals"] = peripherals
    result["candidate_count"] = sum(
        item["profile_match"] in {"strong", "possible"} for item in peripherals
    )
    if not peripherals:
        result["status"] = "no-usb-peripherals"
        result["warnings"].append(
            "No non-root-hub USB device is visible; attach or USB-pass-through the powered Dock board."
        )
    elif result["candidate_count"]:
        result["status"] = "candidates-found-unverified"
        result["warnings"].append(
            "Descriptor matching is not target verification; no JTAG endpoint was opened."
        )
    else:
        result["status"] = "peripherals-found-no-profile-match"
        result["warnings"].append(
            "USB peripherals are visible, but none can be associated with this board profile."
        )
    return result
