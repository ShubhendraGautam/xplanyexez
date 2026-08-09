# M1 physical-platform validation

M1 requires successful qualification on at least five materially different
physical platforms. A VM, container, WSL instance, or five machines with the
same board/firmware family does not satisfy that gate.

## Qualification procedure

Build the standalone scanner once; it contains only project code and requires
only Python 3.10 or newer on the target:

```sh
python3 tools/build_zipapp.py --output dist/hwprobe.pyz
sha256sum dist/hwprobe.pyz
```

Copy `hwprobe.pyz` to each owned and authorized physical machine along with its
SHA-256. Verify the digest, then run:

```sh
evidence_dir="private-evidence-$(date +%Y%m%d-%H%M%S)"
./hwprobe.pyz scan \
  --redaction none \
  --evidence-dir "$evidence_dir" \
  --output "$evidence_dir/inventory.json"

manifest=$(find "$evidence_dir/runs" -type f -name '*.json' -print -quit)
./hwprobe.pyz qualify \
  "$manifest" --evidence-dir "$evidence_dir"
```

The private inventory and evidence directory may contain serial numbers and
other identifiers. Do not commit them. Record only the redacted qualification
summary and the operator attestation below.

An inventory qualifies at the software layer only when:

- schema and cross-field invariants pass;
- all registered M1 handlers ran;
- no handler failed, timed out, or was blocked;
- every partial result has an audited explanation;
- every referenced raw evidence object exists and matches both digest and size.

The tool reports `physical-candidate` when it sees no obvious virtualization
marker, but this is deliberately not proof. The operator must attest that the
scan booted on the named physical target and that passthrough/virtualization did
not substitute the platform being claimed.

## Current matrix

| Slot | Platform class | CPU architecture | Firmware/boot | Distinguishing buses/devices | Software qualified | Physical attestation | Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Development | WSL2 VM | x86-64 | virtualized | synthetic Hyper-V platform | yes, 2026-08-09 | not physical | 9 handlers, 259 records, 1,298 observations; private evidence verified |
| 1 | laptop | pending | pending | pending | pending | pending | pending |
| 2 | desktop/workstation | pending | pending | pending | pending | pending | pending |
| 3 | server | pending | pending | pending | pending | pending | pending |
| 4 | Arm or RISC-V board | pending | pending | pending | pending | pending | pending |
| 5 | materially different system | pending | pending | pending | pending | pending | pending |

Suggested diversity is not mandatory, but each chosen platform must add a real
hardware/firmware/transport difference. Record date, tool commit, owner-approved
scope, power-cycle state, privilege level, handler statuses, partial-coverage
reasons, evidence verification counts, and operator signature/attestation.
