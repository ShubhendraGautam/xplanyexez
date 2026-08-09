from __future__ import annotations

import hashlib
import json
import stat
import tempfile
import unittest
from pathlib import Path

from hwprobe.handlers.base import Handler
from hwprobe.io import read_text
from hwprobe.model import HandlerReport, ProbeLevel
from hwprobe.policy import RedactionMode, ScanPolicy
from hwprobe.provenance import ContentAddressedStore, EvidenceError, verify_evidence
from hwprobe.scanner import scan


class EvidenceHandler(Handler):
    name = "evidence"
    category = "test"

    def probe(self) -> HandlerReport:
        report = HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)
        report.facts["version"] = read_text(Path("/proc/version"))
        return report


class ProvenanceTests(unittest.TestCase):
    def test_store_deduplicates_and_verifies_objects(self) -> None:
        data = b"raw evidence"
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedStore(Path(directory))
            store.put(digest, data)
            store.put(digest, data)
            self.assertEqual(store.stats.objects_seen, 2)
            self.assertEqual(store.stats.objects_written, 1)
            self.assertEqual(store.read_verified(digest), data)

    def test_store_rejects_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedStore(Path(directory))
            with self.assertRaises(EvidenceError):
                store.put("0" * 64, b"different")

    def test_store_detects_corrupt_existing_object(self) -> None:
        data = b"raw evidence"
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedStore(Path(directory))
            store.put(digest, data)
            store.object_path(digest).write_bytes(b"corrupt")
            with self.assertRaises(EvidenceError):
                store.put(digest, data)

    def test_scan_writes_private_manifest_and_verifiable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedStore(Path(directory))
            policy = ScanPolicy(redaction=RedactionMode.NONE)
            document = scan([EvidenceHandler], policy=policy, host_id="test-host", evidence_store=store)
            run_manifest = Path(directory) / "runs" / f"{document['run']['run_id']}.json"
            private_document = json.loads(run_manifest.read_text(encoding="utf-8"))
            result = verify_evidence(private_document, ContentAddressedStore(Path(directory)))
            self.assertGreater(result["objects_verified"], 0)
            self.assertEqual(document["run"]["evidence_store"]["objects_written"], 1)
            self.assertEqual(stat.S_IMODE(run_manifest.stat().st_mode), 0o600)
            digest = private_document["reports"][0]["provenance"][0]["sha256"]
            self.assertEqual(stat.S_IMODE(store.object_path(digest).stat().st_mode), 0o600)

    def test_verification_checks_declared_size(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ContentAddressedStore(Path(directory))
            policy = ScanPolicy(redaction=RedactionMode.NONE)
            document = scan([EvidenceHandler], policy=policy, host_id="test-host", evidence_store=store)
            document["reports"][0]["provenance"][0]["size"] += 1
            with self.assertRaises(EvidenceError):
                verify_evidence(document, store)


if __name__ == "__main__":
    unittest.main()
