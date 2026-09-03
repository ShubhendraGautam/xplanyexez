# P2 active-experiment contract

P2 sends an active but intended-to-be-reversible command to hardware. It is not
part of the passive `scan` command. A deterministic request is safer to review
than a random or arbitrary write, but its risk is determined by device behavior,
not by the byte-generation method.

## Non-bypassable flow

1. Create a new manifest with `hwprobe p2 init`.
2. Replace every placeholder and select a code-reviewed adapter and named
   allowlisted command.
3. Obtain every legal, spectrum, facility, data, and third-party permission.
4. The declared legal owner reads the disclaimer, types their legal name and the
   manifest-specific challenge, and protects the signature with a passphrase.
5. Verify the manifest and authorization immediately before the run.
6. Run with a private evidence directory. One experiment UUID may be consumed
   only once in that directory.

There is intentionally no `--yes`, `--force`, environment-variable acceptance,
generic hex payload, raw file-descriptor adapter, or remote-target mode.

## Manifest invariants

The P2 manifest is bound to exactly one UUID and one local physical target. It
must declare the legal owner's name, stable target identity, interface, adapter,
named command, structured parameters, serialized-request SHA-256, timeout,
response limit, known side effects, maximum credible harm, data classes, tested
recovery plan, and whether RF transmission is possible.

The initial policy permits one attempt, an authorization window of at most 24
hours, a maximum 30-second operation timeout, and a maximum 1 MiB response. It
rejects remote, shared, production, and life-safety targets. It currently permits
only `hardware-metadata` and `hardware-identifiers` data classes. If RF
transmission is possible, an authorization reference is mandatory.

## Owner signature

The authorization contains the complete attestation, typed-name challenge,
manifest digest, target ID, operator/owner name, signing and expiry times, and a
passphrase-protected HMAC using PBKDF2-HMAC-SHA256. Any manifest change
invalidates it. The passphrase is never stored.

This is a software execution interlock and self-attestation, not a government
digital signature, identity check, proof of title, professional certification,
legal opinion, or substitute for required consent or licences. A copied
authorization could be reused with a copied evidence store, so procedural custody
and access control remain necessary.

## Adapter rule

`src/hwprobe/p2_adapters.py` starts with an empty registry. An adapter may be
registered only after protocol-specific review. It must:

- expose named commands rather than arbitrary payloads;
- validate structured parameters and serialize deterministically;
- document opcode semantics and device/firmware applicability;
- independently re-read and match the physical target identity immediately before
  dispatch;
- transmit exactly the request passed by the runner;
- enforce its deadline and response bound;
- avoid state-changing, reserved, vendor-unknown, or broadcast commands; and
- have hardware-in-the-loop tests for timeout, malformed response, hot-unplug,
  repeated command, recovery, and unexpected reset.

The runner recomputes the serialized request digest before opening the trace. A
digest mismatch or non-allowlisted command stops before hardware access.

An adapter descriptor is not an installed transport. `hwprobe p2 adapters` may
show planned commands and blocking validation work, while `p2 run` continues to
reject the adapter until its reviewed implementation is separately registered.

## Evidence ordering

Before dispatch, the runner stores the exact request bytes in the private
content-addressed store and fsyncs an `authorization_verified` event followed by
`request_committed_before_dispatch`. It records the bounded response afterward.
Failures append an `experiment_stopped` event when the evidence channel remains
available.

The evidence store is owner-only but is not encrypted by this program. Place it
on an encrypted filesystem or encrypted volume, restrict access, and apply the
retention/deletion plan from the legal checklist.
