# FPGA board discovery and staged probing

The first supported board profile is `tang-primer-25k-dock`, for an owned
Sipeed Tang Primer 25K core board installed in its full Dock board. The profile
records the GW5A-25 family, `GW5A-LV25MG121` package-level part name, expected
JTAG IDCODE `0x0001281b`, eight-bit JTAG instruction register, BL616 Dock
debugger, and the FT2232 transport hint used by openFPGALoader.

These are compatibility expectations, not proof that an attached USB device is
the board. In particular, the project does not assume a VID/PID: Sipeed debugger
firmware and host driver choices may change the presented descriptors.

## Safe discovery stage

With the powered Dock connected or passed through to the VM, run:

```sh
PYTHONPATH=src python3 -m hwprobe fpga boards
PYTHONPATH=src python3 -m hwprobe fpga discover --board tang-primer-25k-dock --pretty
```

Discovery reads sysfs USB device and interface descriptors. It does not open an
endpoint and reports `transmitted_bytes: 0`. USB serial values are hashed by
default. To capture the exact serial for a private target manifest, redirect an
explicit unredacted run to an access-controlled file:

```sh
umask 077
PYTHONPATH=src python3 -m hwprobe fpga discover \
  --board tang-primer-25k-dock --include-identifiers --pretty \
  > primer25k-private.json
```

Do not publish that report without removing stable identifiers. A descriptor
match remains unverified until the protocol adapter rechecks the physical target
at execution time.

## P2 activation gate

`hwprobe p2 adapters` lists `tang-primer-25k-jtag`, but it is deliberately not
executable. The initial planned command is only `read-idcode`. Registration is
blocked until all of the following are complete:

- capture the real Dock VID/PID, product/manufacturer strings, serial, USB
  configuration/interface layout, bound drivers, and debugger firmware;
- review the precise FT2232/MPSSE and JTAG serialization and response parsing;
- ensure the adapter selects one exact local device and revalidates its identity;
- test timeout, hot-unplug, malformed/short response, unexpected reset, repeated
  query, and recovery on the owned isolated board; and
- generate, review, and interactively sign the per-run P2 manifest.

The adapter must never expose a caller-provided hex payload or arbitrary JTAG
instruction. Programming SRAM/flash, erase, reset, boundary scan, debug access,
and UART transmission are outside this first command's scope.

## Profile sources

- [Sipeed Tang Primer 25K documentation](https://github.com/sipeed/sipeed_wiki/blob/main/docs/hardware/en/tang/tang-primer-25k/primer-25k.md)
- [Sipeed onboard-debugger firmware documentation](https://github.com/sipeed/sipeed_wiki/blob/main/docs/hardware/zh/tang/common-doc/update_debugger.md)
- [openFPGALoader board registry](https://github.com/trabucayre/openFPGALoader/blob/master/src/board.hpp)
- [openFPGALoader Gowin device implementation](https://github.com/trabucayre/openFPGALoader/blob/master/src/gowin.cpp)
