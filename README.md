# Xplanyexez

Xplanyexez is a hardware discovery and experimentation framework. Its purpose is
not merely to label devices, but to build an evidence-backed description of what
the machine can actually do and provide a controlled path toward deeper probes.

The first milestone is Linux-first and read-only. It inventories CPU, memory,
PCI, USB, block, network, firmware, graphics, and the remaining Linux bus
topology without external dependencies. Later milestones can add privileged
helpers and bare-metal probes without changing the inventory format.

## Probe levels

| Level | Meaning | Default |
| --- | --- | --- |
| 0 | Enumerate topology; do not communicate with a device | yes |
| 1 | Read documented, side-effect-free attributes | yes |
| 2 | Send active but reversible queries | explicit opt-in |
| 3 | Change device state; recovery path required | isolated test bench only |
| 4 | Potentially destructive or irreversible experiments | separate tooling |

The key rule is evidence before interpretation. A reported claim includes its
source path, and unknown values remain unknown rather than being guessed.

## Run it

Python 3.11 or newer is recommended; the scanner uses only the standard library.

```sh
PYTHONPATH=src python3 -m hwprobe scan --pretty
PYTHONPATH=src python3 -m hwprobe scan --output inventory.json
PYTHONPATH=src python3 -m hwprobe scan --handler linux-cpu --handler linux-pci
PYTHONPATH=src python3 -m hwprobe scan --redaction none --output private-inventory.json
PYTHONPATH=src python3 -m hwprobe scan --evidence-dir private-evidence --output inventory.json
PYTHONPATH=src python3 -m hwprobe verify-evidence private-evidence/runs/RUN_ID.json --evidence-dir private-evidence
PYTHONPATH=src python3 -m hwprobe qualify private-evidence/runs/RUN_ID.json --evidence-dir private-evidence
PYTHONPATH=src python3 -m hwprobe handlers
PYTHONPATH=src python3 -m hwprobe validate inventory.json
```

Running as root may expose more read-only attributes, but is not required. The
current code never writes to a device, sysfs, procfs, or firmware interface.
Handlers run in isolated worker processes with deadlines. Identifiers such as
hostnames, MAC addresses, UUIDs, and serial numbers are redacted by default;
`--redaction none` is an explicit choice for a private raw report.

`--evidence-dir` is also explicit because it stores the exact bytes observed by
the handlers, including identifiers. Objects are deduplicated by SHA-256 and a
private unredacted run manifest is written with owner-only permissions. Keep
that directory out of source control. See the [provenance contract](docs/provenance.md).

## Design

Each hardware category is owned by a handler. Handlers emit a common record:

- a stable category and best-effort identity;
- raw facts with minimal interpretation;
- evidence paths for auditability;
- warnings and permission failures rather than silent omissions;
- the highest probe level actually used.

The generic bus handler provides coverage for devices that do not yet have a
specialist. Specialist handlers then go deeper without hiding the underlying
topology.

Project planning and operating documents:

- [Architecture](docs/architecture.md): invariants and the deeper-probing roadmap.
- [Exhaustive project checklist](docs/project-checklist.md): features, coverage,
  feasibility, restrictions, and completion gates.
- [Legal and authorization checklist](docs/legal.md): ownership, privacy,
  reverse engineering, radio, export, and disclosure gates.
- [Risk and blast-radius policy](docs/risk-and-blast-radius.md): containment,
  recovery, and experiment approval requirements.
- [Provenance contract](docs/provenance.md): raw evidence layout, verification,
  privacy, and future offline decoder requirements.
- [Platform validation](docs/platform-validation.md): repeatable qualification
  procedure and the five-physical-platform M1 matrix.
