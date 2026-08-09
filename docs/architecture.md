# Architecture

## Principles

1. **Observe before acting.** A new handler starts at levels 0–1 and earns
   access to active operations through tests and review.
2. **Preserve evidence.** Facts identify the file, register, command response,
   or trace from which they came.
3. **Do not confuse access with capability.** A permission failure means
   “unknown from this probe,” not “unsupported by the hardware.”
4. **Separate mechanism from interpretation.** A small probe mechanism gathers
   bytes; versioned decoders turn bytes into claims.
5. **Contain failure.** Timeouts, exceptions, malformed firmware, and one broken
   handler must not prevent the rest of the inventory.
6. **Make active probing explicit.** Probe level, operator consent, preconditions,
   timeout, expected side effects, and recovery procedure belong in the API.

## Layers

```text
CLI / experiment runner
        |
inventory coordinator -------- policy and capability gates
        |
category handlers ------------ CPU, PCI, USB, storage, firmware, ...
        |
probe transports ------------- sysfs, ioctl, CPUID, MSR, config space, JTAG
        |
versioned decoders ----------- raw bytes -> evidence-backed claims
```

The initial implementation combines handlers and read-only sysfs/procfs
transports to keep the bootstrap dependency-free. Native transports should
eventually live in a small memory-safe privileged service. The coordinator
should remain unprivileged.

## Inventory schema

The JSON document is self-describing and forward-compatible:

- `schema_version`: contract version;
- `run`: unique run ID, pseudonymous stable host ID, timestamps, tool identity,
  requested handlers, policy, and effective probe depth;
- `reports`: one result per registered handler;
- `reports[].devices`: normalized device records with host-scoped stable IDs;
- `reports[].evidence`: paths read or enumerated;
- `reports[].warnings`: partial-access and decoding problems.
- `reports[].coverage`: successful, missing, denied, failed, and oversized read
  counts plus the number of evidence sources and devices;
- `reports[].capabilities`: declared levels, privileges, locks, side effects,
  hazards, and timeout.

Consumers must tolerate new keys and unknown handler names.

Schema 1.2 is described by `schema/inventory.schema.json` and reinforced by
runtime invariants such as unique stable device IDs. Output redaction happens
after validation and the redacted result is validated again.

Every audited read, binary capture, symlink resolution, and directory listing
also emits a provenance observation with outcome, source, media type, byte count,
and SHA-256 when content was obtained. Raw bytes are retained only when the
operator explicitly enables the private content-addressed evidence store.
See [provenance.md](provenance.md).

## Roadmap

### Milestone 1: trustworthy inventory

- Read-only Linux topology and attributes.
- Deterministic JSON and per-handler error isolation.
- Snapshots usable in tests and for before/after comparison.

### Milestone 2: native read-only probes

- Per-core CPUID leaves and topology correlation.
- PCI/PCIe configuration-space and capability-chain decoding.
- NVMe identify/log pages and SCSI inquiry/VPD through pass-through IOCTLs.
- EDID, DRM properties, input capabilities, ALSA topology, SMBIOS, ACPI, and
  device-tree raw-table capture.
- SPD EEPROM reads only where the controller and platform permit safe access.

The first native slice, **x86 CPUID**, executes in user space with per-logical-CPU
affinity. It retains every queried `(leaf, subleaf, eax, ebx, ecx, edx)` tuple,
audits the raw response bytes, and layers named feature claims on top. Documented
basic, extended, structured, and hypervisor namespaces are bounded independently;
reserved-input exploration remains gated on an experiment manifest rather than
an open-ended loop.

### Milestone 3: controlled active experiments

- A manifest for preconditions, locks, timeouts, expected mutations, rollback,
  and power-cycle recovery.
- Device isolation through IOMMU groups, driver unbind/rebind, or a dedicated
  fixture where appropriate.
- Trace capture around every experiment so surprising behavior is reproducible.

### Milestone 4: non-OS transports

- Bootable probe image and UEFI application.
- External debug adapters (JTAG/SWD), logic analyzer, UART, and power control.
- Cross-validation of kernel, firmware, and direct observations.

“Every hardware device” is an asymptote: some components are not enumerable,
some interfaces are fused off, and some observations require destructive
decapsulation. The framework therefore reports coverage and uncertainty instead
of claiming completeness it cannot demonstrate.
