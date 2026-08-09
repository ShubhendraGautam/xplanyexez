from hwprobe.handlers.block import BlockHandler
from hwprobe.handlers.buses import BusTopologyHandler
from hwprobe.handlers.cpu import CpuHandler
from hwprobe.handlers.firmware import FirmwareHandler
from hwprobe.handlers.graphics import GraphicsHandler
from hwprobe.handlers.memory import MemoryHandler
from hwprobe.handlers.network import NetworkHandler
from hwprobe.handlers.pci import PciHandler
from hwprobe.handlers.usb import UsbHandler

HANDLERS = (
    CpuHandler,
    MemoryHandler,
    PciHandler,
    UsbHandler,
    BlockHandler,
    NetworkHandler,
    GraphicsHandler,
    FirmwareHandler,
    BusTopologyHandler,
)

__all__ = ["HANDLERS"]
