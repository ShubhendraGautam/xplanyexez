# Risk, feasibility, and blast-radius policy

Probe depth says how directly Xplanyexez talks to hardware. Blast radius says
what can be harmed if the probe or device behaves unexpectedly. They are related
but not interchangeable.

## Probe depth

| Level | Operation | Examples | Default policy |
| --- | --- | --- | --- |
| P0 | Topology only | Enumerate buses and relationships | allowed |
| P1 | Passive/read-only | CPUID, descriptors, documented status | allowed after handler review |
| P2 | Active/reversible | Identify command, diagnostic, function reset | explicit manifest and consent |
| P3 | Stateful | Unbind, power-state change, register/firmware write | isolated test bench |
| P4 | Destructive/irreversible | Fuses, erase, overvoltage, glitch, decap | separate tooling and approval |

A documented read can still be P2 if it clears state, wakes media, acknowledges
an event, moves a FIFO, or has device-specific side effects.

## Blast-radius scale

| Radius | Maximum credible consequence | Typical examples |
| --- | --- | --- |
| B0 | Probe process/report only | Parser crash, incomplete evidence |
| B1 | One logical function; recoverable | Function reset, temporary link loss |
| B2 | One physical device or its data | Device hang, firmware recovery, scratch-media loss |
| B3 | Whole test host or attached bus/domain | Host crash, shared reset, filesystem loss, boot failure |
| B4 | Physical lab equipment or local people/facility | Electrical damage, battery fire, hazardous heat/laser/RF exposure |
| B5 | External people, networks, spectrum, infrastructure, tenants, or public | Interference, privacy breach, service outage, safety event |

B5 experiments are outside project scope. Any unexpected expansion to B5 is an
incident and an automatic stop.

## Risk evaluation

Every P2+ manifest records these independently:

- **severity:** maximum credible harm, not the hoped-for outcome;
- **likelihood:** evidence-based estimate including unknown hardware behavior;
- **exposure:** number of devices, people, records, networks, bands, and duration;
- **detectability:** whether failure is noticed before harm expands;
- **recoverability:** automatic rollback, reset, reflash, rework, replacement, or
  no practical recovery;
- **confidence:** quality of schematics, specification, decoder, fixture, and
  prior runs;
- **residual risk:** risk remaining after controls.

Unknowns increase risk; they do not count as zero. The approved radius is the
smallest physical and administrative boundary that truly contains the worst
credible failure.

## Approval matrix

| Requested operation | Maximum radius | Required gate |
| --- | --- | --- |
| P0–P1 | B0–B1 | automated policy plus handler tests |
| P1 with secrets/personal data | B1–B3 | data plan and explicit operator consent |
| P2 | B1 | reviewed manifest, timeout, rollback, local console |
| P2 | B2–B3 | isolated host, backup, watchdog, remote log, power control |
| P3 | B1–B3 | two-step human approval and dedicated expendable target |
| P3 | B4 | specialist safety review, supervised fixture, emergency stop |
| P4 | B2–B4 | separate runner, named approver, expendable sample, disposal plan |
| Any | B5 | prohibited |

## Preflight checklist for every P2+ experiment

### Authority and scope

- [ ] Legal checklist complete and authorization attached to the run.
- [ ] Exact physical devices, functions, buses, addresses, and interfaces listed.
- [ ] Shared reset, power, clock, interrupt, DMA, IOMMU, storage, network, and
  management domains mapped.
- [ ] Expected and maximum credible blast radius declared and approved.
- [ ] Stop conditions and a person with stop authority identified.

### Target preparation

- [ ] Target is not production, shared tenancy, life-safety, medical, in-motion,
  critical infrastructure, or providing a service to uninvolved people.
- [ ] Valuable storage is removed or fully backed up and recovery was tested.
- [ ] Credentials, keys, personal data, and unrelated peripherals are removed.
- [ ] Firmware, configuration, calibration, partition tables, device identity,
  and current state are backed up where readable and lawful.
- [ ] Replacement value, repairability, anti-rollback, fuse state, and warranty
  consequence are understood.
- [ ] Known-good recovery image, boot media, console, external programmer, and
  replacement parts are present when relevant.

### Containment

- [ ] Network physically disconnected or attached only to an isolated owned peer.
- [ ] RF uses shielding/conducted coupling/dummy load and independent spectrum
  monitoring where transmission is possible.
- [ ] Complete IOMMU and reset groups isolated; DMA cannot reach valuable memory.
- [ ] Bus peers that share reset/power or can be harmed are removed.
- [ ] Independent watchdog and remotely controlled power cutoff tested.
- [ ] Current limit, voltage limit, thermal cutoff, fuse, ESD protection, and
  correct level shifting installed as applicable.
- [ ] Battery work has fire-resistant containment and a safe evacuation/disposal
  plan; damaged/swollen cells are not energized.
- [ ] Mains, high voltage/current, lasers, moving machinery, pressure, chemicals,
  hot surfaces, and RF exposure receive specialist controls or are excluded.

### Experiment quality

- [ ] Hypothesis, baseline, controls, exact inputs, expected outputs, and maximum
  duration are written down.
- [ ] Command/register semantics and access width/endian/alignment verified from
  more than one source where possible.
- [ ] Read side effects, reserved bits, write-one-to-clear/set, self-clearing,
  posted writes, ordering, cache, DMA, and interrupt behavior considered.
- [ ] Inputs are bounded; rate, iteration, power, temperature, voltage, frequency,
  and duty-cycle limits are machine enforced.
- [ ] Dry run/replay/simulation and least-invasive version completed first.
- [ ] Rollback and power-cycle recovery were rehearsed, not merely documented.
- [ ] Evidence channel is independent enough to survive the expected host crash.

## Runtime interlocks

- [ ] Two-step confirmation states target ID, probe level, blast radius, and
  irreversible consequence; generic `--force` is insufficient.
- [ ] Privileged broker allowlists exact operations and refuses undeclared targets.
- [ ] Exclusive resource locks prevent another handler or OS driver from racing.
- [ ] Heartbeat watchdog aborts or power-cycles on timeout.
- [ ] Independent sensors enforce power, current, temperature, RF, and duration
  limits where relevant.
- [ ] Append-only remote trace records commands before issue and outcomes after.
- [ ] A failed verification, changed device identity, hot-plug, lost console,
  unexpected reboot, new bus error, or containment alarm triggers stop.
- [ ] Rollback never continues blindly after the pre-rollback state differs from
  the expected state.

## Postflight checklist

- [ ] Stop active traffic and restore configuration in reverse dependency order.
- [ ] Verify reset, driver, firmware, clocks, power, thermal policy, network, boot,
  and data integrity against the baseline.
- [ ] Cold-power-cycle when the experiment's state lifetime is uncertain.
- [ ] Collect error logs, AER/RAS/SMART/EDAC counters, thermal/power excursions,
  and physical inspection results.
- [ ] Hash and seal evidence; record missing/truncated evidence explicitly.
- [ ] Quarantine a target with unexplained behavior; do not return it to normal
  use merely because it boots.
- [ ] Record actual blast radius, recovery actions, sample damage, and surprises.
- [ ] File an incident and raise future controls if actual behavior exceeded the
  approved model.
- [ ] Sanitize or dispose of damaged/e-waste samples through the approved route.

## Handler-specific hazards

| Area | Non-obvious blast radius | Minimum containment |
| --- | --- | --- |
| CPU/MSR | all cores, voltage/frequency rails, machine-check/reset | serial console, watchdog, power cycle |
| Memory | silent corruption outside test buffer, persistent poison | bootable target, no valuable storage, ECC logs |
| PCIe/CXL | shared reset/IOMMU domain, DMA, fabric hang | entire group assignment, peers removed |
| USB/PD | host-controller reset, overcurrent, wrong negotiated voltage | sacrificial hub, current limiter, PD analyzer |
| Storage | controller-wide reset, namespace loss, delayed corruption | scratch media, full backup, power-cut fixture |
| GPU | display loss, host memory DMA, thermal/power excursion | secondary adapter/console, resettable target |
| Firmware/EC | unbootable board, battery/thermal control loss | external programmer, power/battery disconnect |
| I²C/SMBus | clear-on-read device, bus lock, PMIC/clock/EEPROM mutation | known schematic, address denylist, power cutoff |
| SPI/flash | corrupted boot/calibration/identity | verified full dump, clip/programmer, spare chip |
| GPIO | shorts, contention, unintended reset/power enable | direction/voltage proof, series resistance |
| JTAG/SWD | CPU halt, flash erase, security-state change | owned expendable target, image backup |
| Battery/PMBus | fire, overcharge, disabled protection | supervised fire-safe fixture, independent cutoff |
| RF | interference, regulatory breach, external receivers | shield/conducted path, dummy load, license gate |
| Camera/mic/biometric | privacy breach rather than hardware damage | content-off default, consent, encrypted evidence |
| BMC/management | remote fleet-wide control and credentials | isolated management network, scoped account |

## Recovery tiers

- **R0:** retry/restart the probe process.
- **R1:** restore registers/configuration or reset one function.
- **R2:** reset/power-cycle the device and rebind/re-enumerate it.
- **R3:** cold boot host, restore data/configuration, or reflash through documented
  recovery.
- **R4:** external programming, board rework, component replacement, or sample
  disposal.
- **R5:** no recovery under project control.

P2 requires a tested R1/R2 route. P3 requires an available R3/R4 route and an
expendable target. P4 accepts R4/R5 only through the separate destructive-work
process.
