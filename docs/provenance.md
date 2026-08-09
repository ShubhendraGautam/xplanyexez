# Provenance and evidence-store contract

Schema version 1.2 makes passive observations auditable without placing raw
system bytes directly in the shareable inventory.

## Observation record

Each handler report contains `provenance[]`. An observation records:

- `source`: file, directory, or symlink path;
- `sequence`, `transport`, and `duration_us`: handler-local ordering, the
  acquisition mechanism, and elapsed operation time;
- `operation`: `read_text`, `read_binary`, `read_link`, or `list_directory`;
- `status`: success, absence, permission denial, I/O failure, size limit, or
  output redaction;
- `sha256` and `size`: raw bytes when the operation succeeded;
- `media_type`: text, binary, symlink, or directory-list representation;
- `detail`: a bounded error/limit explanation, never an exception traceback.

Directory-list objects contain sorted entry names separated by newline. Symlink
objects contain the link's raw target text. Text objects contain bytes exactly as
read, before decoding or whitespace removal. Firmware objects contain the
bounded raw bytes used to calculate the inline table digest.

## Store layout

The store is opt-in through `--evidence-dir` because its contents are private:

```text
STORE/
  objects/sha256/ab/abcdef...   exact raw bytes, mode 0600
  runs/RUN-UUID.json            unredacted inventory, mode 0600
```

Directories are created for owner access and objects are written through a
temporary file followed by an atomic rename. Identical content is stored once,
even if it was read by multiple devices or handlers. Existing objects are never
trusted merely by filename: `verify-evidence` reads and hashes every referenced
object.

## Privacy contract

- The normal inventory defaults to `identifiers` redaction.
- Facts such as serials, UUIDs, MAC addresses, and asset tags are removed.
- Provenance digests for files whose names directly identify those fields are
  removed as well; short identifiers can be recovered by guessing their hashes.
- `strict` additionally removes facts, evidence paths, provenance records,
  names, and host identity from the shared document.
- The private run manifest is intentionally unredacted so that it can verify all
  collected objects. It must not be published accidentally.
- The evidence store does not yet perform semantic secret scanning. Operators
  must review exports, and ordinary handlers must not request credentials,
  memory contents, user files, TPM private material, or packet payloads.

## Verification and replay

```sh
PYTHONPATH=src python3 -m hwprobe verify-evidence \
  STORE/runs/RUN-UUID.json --evidence-dir STORE
```

Verification proves that all successful observations referenced by that
manifest are present and content-correct. It does not prove that the source
hardware returned truthful data or that the machine was not altered before the
scan.

The retained bytes form the offline replay contract for versioned decoders:
decoders must accept bytes plus observation metadata without reopening the live
source. Current handlers still combine acquisition and some decoding, so full
handler re-execution from the store remains an unchecked roadmap item. New
native transports must preserve this same source/input/output/digest split.
