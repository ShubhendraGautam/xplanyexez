from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hwprobe.handlers import HANDLERS
from hwprobe.policy import RedactionMode, ScanPolicy
from hwprobe.provenance import ContentAddressedStore
from hwprobe.qualification import qualify_inventory
from hwprobe.scanner import scan


class QualificationTests(unittest.TestCase):
    def test_full_scan_requires_evidence_store_for_qualification(self) -> None:
        policy = ScanPolicy(redaction=RedactionMode.NONE)
        document = scan(HANDLERS, policy=policy, host_id="test-host")
        result = qualify_inventory(document)
        self.assertFalse(result["qualified"])
        evidence_check = next(check for check in result["checks"] if check["name"] == "evidence-store")
        self.assertFalse(evidence_check["passed"])

    def test_full_scan_with_evidence_can_qualify_software_layer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            store = ContentAddressedStore(root)
            policy = ScanPolicy(redaction=RedactionMode.NONE)
            document = scan(HANDLERS, policy=policy, host_id="test-host", evidence_store=store)
            result = qualify_inventory(document, evidence_dir=root)
        self.assertTrue(result["qualified"])
        self.assertFalse(result["environment"]["counts_toward_physical_m1_gate"])


if __name__ == "__main__":
    unittest.main()
