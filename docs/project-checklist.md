# Exhaustive project checklist

Status as of 2026-08-09. This is the project's living scope and release gate.
An unchecked item is not an implicit promise that every platform can support it;
the feasibility code records what is realistically required.

## Status and feasibility legend

- `[x]`: present in the repository, although it may still need broader hardware
  validation.
- `[ ]`: planned or required before the stated milestone is complete.
- **F0 — portable:** implementable using documented, unprivileged interfaces.
- **F1 — privileged:** needs a narrow privileged helper, raw I/O, or a boot-time
  component.
- **F2 — fixture:** needs owned hardware, device isolation, an external adapter,
  or a controlled RF/electrical setup.
- **F3 — specialist:** needs vendor information, expensive instruments, or
  substantial reverse engineering; success varies by device.
- **F4 — destructive:** may irreversibly alter or physically destroy the sample.
- **F5 — unknowable:** no exposed interface or practical observation can prove
  the claim. Report as unknown; never infer absence.

Feasibility describes access cost, not risk. Probe level and blast radius are
separate controls defined in [risk-and-blast-radius.md](risk-and-blast-radius.md).

## Feasibility summary

| Capability band | Feasibility | Expected result |
| --- | --- | --- |
| OS-visible topology and documented passive attributes | F0 | broad and reliable; already bootstrapped on Linux |
| Architectural CPU queries and userspace API cross-checks | F0–F1 | high feasibility across supported architectures |
| Privileged config space, MSRs, firmware tables, and standard device identify/log commands | F1 | high on owned physical machines with a reviewed broker |
| Boot-time probes and driver-independent device access | F1–F2 | high, but requires isolation and recovery engineering |
| External bus capture, board correlation, JTAG/SWD, and flash programming | F2–F3 | medium; board/vendor knowledge dominates effort |
| Proprietary protocols, embedded controllers, undocumented accelerators, and unknown opcodes | F2–F3 | variable; discoveries likely, completeness unlikely |
| Locked/signed firmware modification and undocumented silicon behavior | F3–F4 | low to variable; legal, cryptographic, fuse, and recovery limits apply |
| Changing fixed silicon into physically absent execution resources | F5 | infeasible; emulation, translation, microcode, or programmable fabric are distinct alternatives |
| Proving no hidden state or capability exists anywhere in a device | F5 | generally impossible; only bounded statements are defensible |

The feasible research objective is therefore stronger than a catalog but more
precise than “unlimited”: enumerate exposed structure, cross-check observers,
systematically test bounded hypotheses, and preserve every unknown.

## Project-wide definition of done

- [ ] Every run has a unique ID, UTC timestamps, tool/build identity, OS/firmware
  context, requested probe level, effective probe level, and policy decision log.
- [ ] Every discovered object has a stable best-effort ID, physical/logical
  relationship, handler owner, facts, raw evidence references, and uncertainty.
- [ ] Every claim distinguishes `observed`, `decoded`, `inferred`, `vendor
  reported`, `unsupported`, `inaccessible`, `not present`, and `not tested`.
- [ ] Every read or command records transport, target, input, output or digest,
  duration, timeout, decoder version, and error without silently dropping data.
- [x] Every handler declares supported probe levels, privileges, locks, side
  effects, prerequisites, maximum runtime, recovery plan, and known hazards.
- [ ] Every active experiment is reproducible from a reviewed manifest.
- [ ] Every state-changing experiment has a verified rollback or is explicitly
  classified as destructive.
- [x] Every output format supports redaction of identifiers, network addresses,
  firmware secrets, user data, and proprietary blobs before sharing.
- [ ] Every platform report includes a coverage ledger and known blind spots; no
  report claims literal completeness without evidence.
- [ ] The scanner remains useful if any handler times out, crashes, loses the
  device, returns malformed data, or lacks permission.
- [ ] Tests cover real fixtures, replayed captures, malformed inputs, timeouts,
  hot-unplug, concurrency, and rollback failure.
- [ ] A legal/authorization record and blast-radius approval accompany every
  Level 2+ run.

## Core framework

### Inventory and orchestration

- [x] Common device and handler report model. **F0**
- [x] Independent handler failure containment. **F0**
- [x] Deterministic evidence ordering and JSON output. **F0**
- [x] Probe-level vocabulary (topology through destructive). **F0**
- [x] Generic Linux bus topology coverage net. **F0**
- [x] Stable run ID and host-scoped stable device-ID strategy across boots.
  **F0–F1**
- [ ] Physical topology graph: contains, attached-to, powered-by, clocked-by,
  driver-bound-to, IOMMU-member-of, and firmware-described-by edges. **F0–F2**
- [x] Handler selection and exclusion controls. **F0**
- [ ] Handler dependency and explicit ordering controls. **F0**
- [x] Per-handler deadlines, worker termination, and stuck-I/O containment.
  **F0–F1**
- [x] Global scan deadline spanning all isolated handlers. **F0–F1**
- [ ] Cooperative operator cancellation with a sealed partial manifest. **F0–F1**
- [ ] Resource arbitration for buses, BARs, controllers, GPIOs, and exclusive
  device access. **F1–F2**
- [ ] Hot-plug/hot-remove event tracking and snapshot consistency detection.
  **F0–F1**
- [ ] Incremental scans, before/after diffs, baselines, and fleet comparisons.
  **F0**
- [ ] Offline decode/re-decode without touching the machine again. **F0**
- [ ] Declarative experiment manifest with schema validation. **F0**
- [ ] Capability negotiation between coordinator, handler, transport, host, and
  test fixture. **F0–F2**
- [ ] Unprivileged coordinator plus small, authenticated privilege broker. **F1**
- [ ] Bootable environment for probes that cannot safely coexist with an OS.
  **F2**
- [ ] UEFI application and minimal bare-metal transport layer. **F2–F3**
- [ ] Remote fixture agent with physical emergency-stop authority. **F2**

### Evidence, analysis, and reporting

- [x] Evidence source paths for current sysfs/procfs facts. **F0**
- [x] Firmware-table hashes with bounded reads. **F0**
- [x] Opt-in content-addressed raw evidence store with SHA-256 deduplication and
  owner-only private manifests. **F0**
- [ ] Cryptographic run manifest and optional operator signature. **F0–F1**
- [ ] Chain-of-custody mode for forensic-quality collection. **F1**
- [ ] Source timestamps, monotonic event timing, clock-quality metadata, and
  optional PTP/GPS correlation. **F0–F2**
- [ ] Confidence score and contradiction tracking for each decoded claim. **F0**
- [ ] Raw-to-decoded provenance graph and versioned decoders. **F0**
- [x] Versioned JSON Schema plus runtime invariant validation. **F0**
- [ ] CBOR, SQLite, text summary, topology graph, and HTML report. **F0**
- [x] Binary-safe evidence capture with enforced per-object size budgets. **F0**
- [ ] Semantic secret scanning before evidence export. **F0**
- [x] Configurable identifier and strict redaction/pseudonymization profiles.
  **F0**
- [ ] Compare observed behavior against datasheet/standard claims. **F0–F3**
- [ ] Anomaly ranking without presenting statistical novelty as capability.
  **F0**
- [ ] Export bundle that includes licenses and provenance but excludes restricted
  vendor material by default. **F0**

### Quality and security

- [x] Unit test for handler isolation and evidence normalization. **F0**
- [x] Fixture-based happy-path and unavailable-root tests for every current
  passive handler. **F0**
- [ ] Exhaustive malformed-input tests for every decoder and transport boundary.
  **F0**
- [ ] Golden captures from x86, Arm, RISC-V, physical Linux, WSL, VMs, servers,
  laptops, and embedded boards. **F0–F2**
- [ ] Hardware-in-the-loop tests on sacrificial devices. **F2**
- [ ] Offline fuzzing of all binary/table/descriptor decoders. **F0**
- [ ] Property tests for length, endian, overflow, capability-chain loop, and
  malformed-table handling. **F0**
- [ ] Privilege-broker threat model, authentication, allowlist, seccomp/sandbox,
  audit log, and independent security review. **F1**
- [ ] Reproducible builds, dependency lock, SBOM, release signing, and provenance.
  **F0**
- [ ] No-network collection mode and deterministic replay mode. **F0**
- [x] Test that the current Level 0–1 transport contains no write-capable open
  flags.
  **F0**
- [ ] Fault injection for unplug, reset, timeout, malformed DMA, full disk, lost
  logging channel, and power interruption. **F0–F2**

## Hardware handler coverage

Each handler must eventually complete the project-wide definition of done. Raw
captures are retained before convenience decoders are applied.

### Processor and execution engines

- [x] Linux logical CPU inventory, `/proc/cpuinfo`, topology, and vulnerability
  exposure. **F0**
- [ ] x86 standard, extended, hypervisor, and vendor CPUID leaves per logical
  processor; retain all leaf/subleaf register tuples. **F0**
- [ ] x86 cache/TLB/topology, XSAVE, performance-monitoring, RDT, SGX/TDX/SEV
  advertisement, and frequency/thermal capability decoding. **F0–F1**
- [ ] Bounded reserved/unknown CPUID input exploration in a disposable execution
  environment. **F1–F2**
- [ ] Architectural and vendor MSR read inventory with allowlisted decoders.
  **F1**
- [ ] MSR write experiments only with per-register rollback and reset recovery.
  **F2–F3**
- [ ] Arm MIDR/MPIDR, feature ID registers, cache topology, SVE/SME, PMU, and
  firmware conduit discovery. **F0–F1**
- [ ] RISC-V ISA/extension, CSR, hart topology, SBI, PMU, vector, and cache-block
  operation discovery. **F0–F1**
- [ ] Microcode/firmware revision correlation and vendor-signed update testing.
  **F1–F2**
- [ ] Instruction behavior harness: architectural result, exceptions, timing,
  counters, power, and cross-core effects. **F1–F3**
- [ ] Unknown opcode sweeps only inside a bounded bare-metal/VM harness with a
  watchdog and no production data. **F2–F3**
- [ ] Accelerator inventory: NPU, DSP, media, crypto, FPGA, DPU, and offload
  engines, including firmware and exposed queues. **F0–F3**
- [ ] Safe overclock, underclock, power-limit, and undervolt characterization
  where the platform explicitly exposes controls. **F2–F3**
- [ ] FPGA/CPLD bitstream and partial-reconfiguration experiments on owned
  development parts. **F2–F3**

Restriction: software cannot “evolve” fixed silicon into gates that do not
exist. It can discover undocumented behavior, activate fused/configurable units,
change microcode where the vendor permits it, synthesize logic in programmable
fabric, or emulate/translate new semantics. Claims must identify which of these
mechanisms produced the capability.

### Memory and coherency

- [x] Linux memory totals, memory blocks, zones, and online state. **F0**
- [ ] Physical address map, NUMA, huge pages, reservations, hot-plug, and memory
  encryption state. **F0–F1**
- [ ] Cache hierarchy, coherency domains, latency/bandwidth, contention, and
  non-uniform behavior measurement. **F0–F2**
- [ ] EDAC/RAS counters, poison handling, patrol scrub, row-remap, and error log
  collection. **F0–F2**
- [ ] SMBIOS memory-array/device decoding. **F0**
- [ ] SPD inventory and checksum/CRC validation over a controller-specific safe
  read path. **F1–F2**
- [ ] DRAM timing/training telemetry when exposed by firmware/controller. **F1–F3**
- [ ] CXL component, link, HDM decoder, mailbox, event, and persistent-memory
  inventory. **F1–F3**
- [ ] NVDIMM/persistent-memory labels, health, namespaces, poison, and flush
  semantics. **F1–F2**
- [ ] Destructive memory characterization only on excluded address ranges or a
  bootable test target. **F2–F4**

### Mainboard, chipset, and platform controllers

- [x] DMI product/board/BIOS identity when exported by the platform. **F0**
- [ ] Chipset/PCH, host bridge, interrupt controller, DMA controller, timers,
  RTC, Super I/O, embedded controller, and clock-generator inventory. **F1–F3**
- [ ] GPIO/pinmux, clock, reset, regulator, and power-domain topology. **F1–F3**
- [ ] Embedded-controller command discovery using vendor protocol or observed
  host transactions, initially read-only. **F2–F3**
- [ ] Board schematic/net correlation and test-point database for owned boards.
  **F2–F3**
- [ ] Boot-phase trace from reset vector through OS handoff. **F2–F3**

### PCI, PCI Express, and CXL

- [x] PCI identity, class, driver, IRQ, NUMA node, power state, and IOMMU group.
  **F0**
- [ ] Full conventional and extended configuration-space capture. **F1**
- [ ] Capability-chain decode: MSI/MSI-X, PCIe, PM, AER, ACS, ATS, PRI, PASID,
  SR-IOV, resizable BAR, LTR, L1 PM, DPC, DOE, IDE, and vendor-specific records.
  **F0–F3**
- [ ] Link width/speed, lane degradation, equalization, ASPM, error counters, and
  topology correlation. **F0–F2**
- [ ] BAR/resource map and read-only register schema supplied by each device
  specialist; never generic blind MMIO reads. **F1–F3**
- [ ] Device reset methods and reset-domain discovery without assuming function
  isolation. **F2**
- [ ] IOMMU-isolated userspace transport for owned endpoint experiments. **F2**
- [ ] PCIe protocol analyzer support and malformed-transaction testing only on a
  closed fixture. **F3–F4**

### USB, Type-C, and Thunderbolt/USB4

- [x] USB identity, strings, class, topology, speed, authorization, and driver.
  **F0**
- [ ] Device/configuration/interface/endpoint/string/BOS descriptor raw capture
  and decode. **F0–F1**
- [ ] Hub topology, bandwidth, power budgets, suspend, reset, and error behavior.
  **F0–F2**
- [ ] USB class specialists: HID, mass storage, audio, video, CDC, DFU, hub, and
  vendor-specific protocols. **F0–F3**
- [ ] Type-C orientation, role, alternate modes, cable/e-marker, and USB Power
  Delivery message capture. **F1–F3**
- [ ] USB4/Thunderbolt router, tunnel, domain, security-level, and authorization
  inventory. **F1–F3**
- [ ] Active descriptor/control-transfer mutation only through a sacrificial
  host/device proxy with current limiting. **F2–F4**

### Storage and persistent media

- [x] Linux block topology, geometry, queue properties, model, serial, state,
  and driver. **F0**
- [ ] NVMe Identify, supported log pages/features, SMART/health, error, firmware,
  endurance, namespace, telemetry, and command-effects data. **F1**
- [ ] ATA/SATA IDENTIFY, SMART, logs, security/sanitize state, NCQ, and transport
  capability. **F1**
- [ ] SCSI/SAS Inquiry, VPD, mode/log pages, defects, sense behavior, and expander
  topology. **F1–F2**
- [ ] eMMC/UFS/SD CID/CSD/EXT_CSD, health, life-time, partitions, RPMB presence,
  and host-controller capability. **F1–F2**
- [ ] Optical, tape, floppy, and legacy-controller specialists. **F1–F3**
- [ ] Non-destructive latency, throughput, queueing, thermal-throttle, power-loss
  notification, and data-retention experiments on scratch media. **F1–F2**
- [ ] Firmware download/activation only with exact image validation, redundant
  recovery path, backup, and expendable media. **F3–F4**
- [ ] Format, sanitize, secure erase, destructive bad-block, and power-cut tests
  only in a separate destructive runner. **F4**

### Graphics and display

- [x] Linux DRM cards/connectors, state, modes, and driver. **F0**
- [ ] GPU identity, engine/topology, memory, clocks, thermals, power, firmware,
  reset support, virtualization, and RAS. **F0–F2**
- [ ] EDID/DisplayID raw capture, checksum, timing, color, HDR, audio, and vendor
  block decoding. **F0–F1**
- [ ] DisplayPort DPCD/link status, HDMI status where legally/documentably
  accessible, panel/backlight, and connector physical topology. **F1–F3**
- [ ] Compute/API capability cross-check across Vulkan, OpenGL, OpenCL, CUDA,
  Level Zero, ROCm, or platform-equivalent stacks. **F0–F2**
- [ ] Controlled command-stream and shader behavior harness on a resettable,
  non-display GPU. **F2–F3**

### Network and radio

- [x] Linux interface identity, MAC, type, state, MTU, carrier, speed, duplex,
  physical/virtual status, and driver. **F0**
- [ ] Ethernet controller, PHY, link modes, EEE, pause, FEC, cable diagnostics,
  counters, EEPROM, firmware, and offload inventory. **F0–F2**
- [ ] SFP/QSFP module identity, diagnostics, thresholds, and compliance data.
  **F1–F2**
- [ ] Wi-Fi PHY/band/channel/chain/capability, regulatory domain, firmware, and
  passive survey without collecting payload content. **F0–F2**
- [ ] Bluetooth controller, HCI/LMP/LE features, firmware, and local adapter
  capability. **F0–F2**
- [ ] Cellular/GNSS/NFC/UWB/LoRa/SDR/radio specialists with jurisdiction-specific
  spectrum policy gates. **F1–F3**
- [ ] Packet and baseband experiments only on owned peers, shielded/conducted
  fixtures, dummy loads, or properly licensed spectrum. **F2–F4**
- [ ] Automatic prevention of transmit outside the approved band, power, time,
  location, antenna, and license manifest. **F1–F2**

### Audio, camera, input, sensors, and human-facing devices

- [ ] ALSA/ASoC codecs, cards, DAIs, controls, sample formats/rates, jack state,
  topology, and firmware. **F0–F2**
- [ ] Camera sensor, media graph, formats, controls, lens/flash, calibration, and
  firmware without capturing imagery by default. **F0–F2**
- [ ] HID report descriptors, input capabilities, LEDs, haptics, touch, pen,
  keyboard, mouse, game controller, and accessibility devices. **F0–F2**
- [ ] IIO/hwmon sensors, scale, calibration, range, rate, trigger, threshold, and
  interrupt behavior. **F0–F2**
- [ ] Biometric devices: hardware/firmware metadata only by default; templates,
  samples, and authentication secrets are excluded from ordinary collection.
  **F1–F3**
- [ ] Microphones/cameras get a visible collection indicator and explicit,
  per-run consent gate before content capture. **F0–F1**

### Power, thermal, battery, and cooling

- [ ] Battery chemistry, design/actual capacity, cycle count, voltage/current,
  temperature, health, charging limits, and smart-battery data. **F0–F2**
- [ ] AC adapter/USB-PD supply, PSU/PMBus, VRM, regulator, power rail, and domain
  inventory. **F1–F3**
- [ ] Thermal zones, sensors, trips, cooling devices, fans, pumps, and throttling
  behavior. **F0–F2**
- [ ] Energy/counter correlation across RAPL, PMU, BMC, PMBus, and external power
  instruments. **F1–F3**
- [ ] Bounded thermal/power sweeps with independent cutoffs. **F2–F3**
- [ ] Battery charge/discharge stress only in a fire-resistant, supervised,
  instrumented fixture; no swollen/damaged cells. **F3–F4**

### Firmware, boot, security, and management

- [x] DMI identity, ACPI table hashes, and EFI-runtime presence. **F0**
- [ ] Raw SMBIOS records and complete decode against a versioned specification.
  **F0**
- [ ] Raw ACPI tables, checksums, AML namespace/static analysis, and OS-visible
  resource correlation. **F0–F2**
- [ ] UEFI variables, memory map, boot entries, Secure Boot state, signature
  databases, TPM event log, and measured-boot correlation. **F0–F1**
- [ ] Device tree, overlays, reserved memory, clocks, resets, regulators, pinctrl,
  interrupts, and bindings. **F0–F2**
- [ ] Firmware volumes, capsules, option ROMs, PCI ROMs, embedded-controller and
  peripheral firmware inventory, extraction, hashing, and offline decode. **F1–F3**
- [ ] TPM 1.2/2.0 capabilities and non-secret public properties; never export
  private/endorsement keys. **F0–F2**
- [ ] BMC/IPMI/Redfish inventory over a dedicated management network with owned
  credentials and explicit authorization. **F1–F2**
- [ ] Firmware update, rollback, and recovery validation on hardware with an
  external programmer or documented recovery mechanism. **F2–F4**
- [ ] Owner-controlled Secure Boot key enrollment or documented disablement as
  a reversible lab configuration, with original keys/settings recorded. **F1–F2**

### Low-speed, embedded, and external buses

- [ ] Enumerate I²C/SMBus, SPI, UART, GPIO, 1-Wire, I3C, CAN, LIN, MDIO, JTAG,
  SWD, LPC/eSPI, mailbox, and sideband controllers. **F1–F3**
- [ ] Passive electrical/protocol capture with voltage-level verification.
  **F2–F3**
- [ ] Address/device discovery only where the bus protocol and controller make
  probing safe; maintain per-address deny lists for destructive-read devices.
  **F2–F3**
- [ ] Logic analyzer, oscilloscope, protocol analyzer, UART bridge, JTAG/SWD
  adapter, flash programmer, and controllable power supply integrations. **F2–F3**
- [ ] Voltage, clock, reset, and power-sequence capture. **F2–F3**
- [ ] Fault injection/glitching requires a destructive manifest, owned target,
  independent power cutoff, and isolated fixture. **F4**
- [ ] Decapsulation, probing, microscopy, FIB, and silicon analysis are tracked
  as external specialist workflows, never routine scanner behavior. **F4–F5**

### Virtual, cloud, and composite hardware

- [ ] Hypervisor, VM generation, virtual CPU leaves, synthetic buses, virtual
  devices, paravirtual interfaces, and passthrough boundaries. **F0–F1**
- [ ] Container namespace/cgroup/device-policy context so “not visible” is not
  mistaken for “not present.” **F0**
- [ ] Cloud instance metadata only with explicit tenant authorization and no
  cross-tenant probing. **F0–F1**
- [ ] Composite-device correlation across PCI/USB functions and shared firmware,
  reset, power, and IOMMU domains. **F0–F2**

## Capability exploration workflow

- [ ] State a falsifiable capability hypothesis before active probing.
- [ ] Record the documented behavior and a reason to suspect additional behavior.
- [ ] Select observables that distinguish capability from caching, emulation,
  undefined behavior, measurement noise, or another component's work.
- [ ] Establish baseline, negative control, positive control, and repeated trials.
- [ ] Bound every input dimension; open-ended brute force is prohibited.
- [ ] Start with passive trace/replay, then valid edge cases, malformed-but-safe
  inputs, state changes, fault conditions, and only lastly destructive tests.
- [ ] Use multiple observers where possible: architectural state, trace, counters,
  power, timing, logic analyzer, and peer-device response.
- [ ] Capture full inputs and raw outputs before interpretation.
- [ ] Repeat across power cycles, firmware versions, temperatures, samples, and
  independent instruments before calling behavior a hardware capability.
- [ ] Distinguish undocumented, implementation-defined, undefined, accidental,
  erratum, security vulnerability, and stable usable capability.
- [ ] Add a regression test and minimal reproducer for every accepted discovery.
- [ ] Route possible vulnerabilities through the disclosure checklist in
  [legal.md](legal.md); do not publish weaponized details by default.

## Restrictions and known limits

- Literal enumeration of “every hardware present” is not always possible.
  Unpowered, fused-off, analog, passive, mux-hidden, inaccessible, or physically
  indistinguishable components may leave no enumerable interface.
- Root privilege does not imply electrical safety, device ownership, or authority
  over remote services, employer assets, managed firmware, other tenants, or RF
  spectrum.
- A kernel, hypervisor, firmware, BMC, or device may virtualize, cache, filter, or
  fabricate observations. The project supports alternative transports to
  cross-check it, but never labels one observer as absolute truth.
- Reads are not universally side-effect-free. Some registers clear on read,
  advance FIFOs, acknowledge interrupts, leak secrets, wake hardware, or hang a
  bus. Unknown register reads therefore require a schema or isolated fixture.
- Writes may affect a larger reset/power/clock/IOMMU/fabric domain than the named
  function. Device-function boundaries are not containment guarantees.
- Timing and performance are environmental observations, not immutable device
  properties. Report power, thermals, clocks, firmware, workload, and variance.
- Vendor strings, firmware tables, and feature bits are claims. Behavioral
  validation is required before treating them as capabilities.
- Microcode, fuses, signed firmware, proprietary protocols, undocumented silicon,
  and encrypted blobs may remain inaccessible. The result is `unknown`, not a
  fabricated bypass or unsupported claim.
- Collection can expose serials, MACs, UUIDs, asset tags, user data, keys, crash
  dumps, and proprietary firmware. Raw reports are private by default.
- Virtual machines and WSL primarily describe the exposed virtual platform. A
  physical boot or external transport is required to characterize the host.

## Authorized access-path (“bypass”) checklist

A bypass is allowed only when it changes the observation path on a system the
operator owns or has written authorization to test. It never expands the target,
accounts, networks, data, radio bands, or users in scope.

- [ ] Permission barrier: use the smallest OS capability or allowlisted privileged
  broker operation; record the authorization and exact resource. **F1**
- [ ] Driver ownership barrier: quiesce, snapshot, unbind, probe, reset, and
  rebind only on an isolated target with console/power recovery. **F1–F2**
- [ ] Kernel abstraction barrier: cross-check with a bootable probe, UEFI app,
  userspace passthrough, or external analyzer. **F1–F3**
- [ ] Hypervisor barrier: rerun on owned bare metal; never attempt a hypervisor or
  cross-tenant escape. **F2**
- [ ] IOMMU barrier: assign the complete isolation group to a controlled probe;
  do not disable system-wide isolation on a shared/production host. **F2**
- [ ] Secure Boot/driver-signing barrier: enroll owner-controlled keys or use a
  documented, reversible lab setting and preserve recovery media. **F1–F2**
- [ ] Flash lock: prefer vendor update/recovery interfaces; external programming
  is restricted to owned, de-energized hardware with a verified backup. **F2–F4**
- [ ] Debug lock/fuse: use vendor-authorized enablement or a sacrificial owned
  sample. Fuses and anti-rollback are not casually defeated. **F3–F4**
- [ ] Proprietary protocol: derive behavior from public material, lawful firmware
  analysis, passive traces, and differential experiments. **F2–F3**
- [ ] Timing barrier: use a microcontroller/FPGA bridge, real-time target, or logic
  analyzer rather than relying on scheduler timing. **F2–F3**
- [ ] Electrical barrier: identify voltage, ground, direction, pull-ups, and
  isolation before connecting; use level shifting/current limiting. **F2**
- [ ] RF barrier: use conducted paths, shielding, dummy loads, receive-only mode,
  or an experimental authorization. **F2–F3**
- [ ] Physical barrier: specialist decapsulation or microprobing only after legal,
  chemical, optical, and electrical review. **F4–F5**
- [ ] If the path would require stolen credentials, evading another party's access
  control, intercepting third-party communications, crossing tenancy, concealing
  activity, or defeating a safety control, stop: it is outside project scope.

## Explicit non-goals

- Unauthorized probing of any device, account, network, vehicle, service, cloud
  tenant, employer system, or protected/critical system.
- Credential, private-key, biometric-template, personal-content, or DRM-content
  extraction as a general inventory feature.
- Persistence, stealth, anti-forensics, exploit deployment, unauthorized access,
  or bypassing monitoring/management imposed by a lawful owner.
- Intentional RF interference, unlicensed out-of-band transmission, cellular
  impersonation, or interception of communications not addressed to the test rig.
- Active experiments on medical, implanted, life-support, aviation, rail, grid,
  industrial safety, public telecom, or in-motion vehicle systems.
- Generic blind writes to MMIO, I/O ports, MSRs, PCI configuration, firmware,
  flash, EEPROM, battery controllers, power controllers, or unknown bus addresses.
- Running destructive probes inside the ordinary inventory command.
- Representing an undocumented behavior as reliable until it survives independent
  reproduction and consequence analysis.

## Milestone gates

### M1 — trustworthy passive inventory

- [x] Initial Linux handlers and JSON report.
- [x] Stable schema and runtime invariant validation.
- [x] Default identifier redaction and configurable profiles.
- [x] Best-effort coverage ledger with successful, absent, inaccessible, failed,
  and size-limited read counts.
- [x] Isolated per-handler timeouts and failure containment.
- [x] Content-addressed provenance store and private manifest verification.
- [x] Fixture coverage for every current passive handler plus inaccessible-root,
  timeout, malformed-handler, policy, redaction, and schema-invariant tests.
- [ ] Exhaustive malformed-field, permission-race, and hot-unplug test matrix.
- [ ] Validate on at least five materially different physical platforms using
  the procedure and attestation matrix in
  [platform-validation.md](platform-validation.md). The current WSL2 development
  qualification passes software checks but does not count as a physical target.

### M2 — native read-only probing

- [ ] CPUID transport/decoder and per-core capture.
- [ ] PCIe configuration transport/decoder.
- [ ] SMBIOS, ACPI, device tree, storage identify/log, USB descriptors, EDID,
  audio/input/sensor, and firmware specialists.
- [ ] Privilege broker and bootable probe reviewed before release.

### M3 — controlled active experiments

- [ ] Manifest/policy engine, resource locks, watchdog, independent recovery,
  before/after state proof, and blast-radius approval.
- [ ] At least one reversible Level 2 experiment passes hardware-in-the-loop fault
  injection without losing evidence or requiring manual repair.

### M4 — state-changing and external-instrument workflows

- [ ] Dedicated fixture controller, remote console, power cycle, current/thermal
  limits, RF containment, and sacrificial-target process.
- [ ] Level 3 tools are separately packaged and cannot be invoked accidentally by
  the inventory CLI.

### M5 — destructive research

- [ ] Separate repository/package, explicit per-run human approval, inventory and
  valuation of expendable samples, hazardous-work review, and disposal plan.
- [ ] No destructive operation is accepted merely because a lower-level route did
  not reveal the desired result.
