from __future__ import annotations

from dataclasses import asdict, dataclass

from hwprobe.p2 import P2Transport


@dataclass(frozen=True, slots=True)
class AdapterDescriptor:
    name: str
    status: str
    target_profiles: tuple[str, ...]
    planned_commands: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


# P2 transports must be code-reviewed and registered by name. Deliberately no
# generic raw-byte, file-descriptor, MMIO, or ioctl adapter is provided.
ADAPTERS: dict[str, P2Transport] = {}

# A descriptor advertises planned work without making it executable. Moving an
# entry into ADAPTERS requires protocol review and hardware-in-the-loop tests.
ADAPTER_DESCRIPTORS = {
    "tang-primer-25k-jtag": AdapterDescriptor(
        name="tang-primer-25k-jtag",
        status="blocked-pending-device-capture-and-hil-validation",
        target_profiles=("tang-primer-25k-dock",),
        planned_commands=("read-idcode",),
        reason=(
            "Dock USB VID/PID, interface layout, serial, and firmware must be captured; "
            "no JTAG bytes are enabled"
        ),
    )
}


def adapter_descriptors() -> tuple[AdapterDescriptor, ...]:
    return tuple(ADAPTER_DESCRIPTORS[name] for name in sorted(ADAPTER_DESCRIPTORS))


def get_adapter(name: str) -> P2Transport:
    try:
        return ADAPTERS[name]
    except KeyError as exc:
        available = ", ".join(sorted(ADAPTERS)) or "none"
        raise ValueError(f"P2 adapter {name!r} is not installed; available adapters: {available}") from exc
