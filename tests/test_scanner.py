from __future__ import annotations

import unittest
import time

from hwprobe.handlers.base import Handler
from hwprobe.model import Device, HandlerReport, ProbeLevel
from hwprobe.policy import RedactionMode, ScanPolicy
from hwprobe.scanner import scan
from hwprobe.schema import SchemaError, validate_inventory


class GoodHandler(Handler):
    name = "good"
    category = "test"

    def probe(self) -> HandlerReport:
        return HandlerReport(self.name, self.category, ProbeLevel.PASSIVE, devices=[Device("one")], evidence=["/b", "/a", "/a"])


class BrokenHandler(Handler):
    name = "broken"
    category = "test"

    def probe(self) -> HandlerReport:
        raise ValueError("bad device data")


class SlowHandler(Handler):
    name = "slow"
    category = "test"

    def probe(self) -> HandlerReport:
        time.sleep(1)
        return HandlerReport(self.name, self.category, ProbeLevel.PASSIVE)


class ActiveHandler(Handler):
    name = "active"
    category = "test"
    default_probe_level = ProbeLevel.ACTIVE
    supported_probe_levels = (ProbeLevel.ACTIVE,)

    def probe(self) -> HandlerReport:
        return HandlerReport(self.name, self.category, ProbeLevel.ACTIVE)


class MalformedHandler(Handler):
    name = "malformed"
    category = "test"

    def probe(self) -> HandlerReport:
        return "not a report"  # type: ignore[return-value]


class ScannerTests(unittest.TestCase):
    def test_handler_evidence_is_deduplicated_and_sorted(self) -> None:
        report = scan([GoodHandler])["reports"][0]
        self.assertEqual(report["evidence"], ["/a", "/b"])
        self.assertEqual(report["devices"][0]["id"], "one")

    def test_broken_handler_is_contained(self) -> None:
        report = scan([BrokenHandler])["reports"][0]
        self.assertIn("ValueError", report["warnings"][0])
        self.assertEqual(report["status"], "failed")

    def test_stable_device_id_is_repeatable_for_same_host(self) -> None:
        policy = ScanPolicy(redaction=RedactionMode.NONE, isolate_handlers=False)
        first = scan([GoodHandler], policy=policy, host_id="test-host")
        second = scan([GoodHandler], policy=policy, host_id="test-host")
        first_id = first["reports"][0]["devices"][0]["stable_id"]
        second_id = second["reports"][0]["devices"][0]["stable_id"]
        self.assertEqual(first_id, second_id)
        self.assertNotEqual(first["run"]["run_id"], second["run"]["run_id"])

    def test_identifier_redaction_is_default(self) -> None:
        document = scan([GoodHandler], host_id="test-host")
        self.assertEqual(document["run"]["hostname"], "<redacted>")
        self.assertTrue(document["reports"][0]["devices"][0]["stable_id"].startswith("device-sha256:"))

    def test_strict_redaction_removes_facts_and_evidence(self) -> None:
        policy = ScanPolicy(redaction=RedactionMode.STRICT, isolate_handlers=False)
        document = scan([GoodHandler], policy=policy, host_id="test-host")
        report = document["reports"][0]
        self.assertEqual(report["facts"], {})
        self.assertEqual(report["evidence"], [])
        self.assertEqual(report["devices"][0]["facts"], {})

    def test_handler_timeout_is_enforced(self) -> None:
        policy = ScanPolicy(handler_timeout_seconds=0.02, redaction=RedactionMode.NONE)
        report = scan([SlowHandler], policy=policy, host_id="test-host")["reports"][0]
        self.assertEqual(report["status"], "timed_out")

    def test_global_scan_deadline_covers_all_handlers(self) -> None:
        policy = ScanPolicy(
            handler_timeout_seconds=1,
            scan_timeout_seconds=0.02,
            redaction=RedactionMode.NONE,
        )
        reports = scan([SlowHandler, GoodHandler], policy=policy, host_id="test-host")["reports"]
        self.assertEqual([report["status"] for report in reports], ["timed_out", "timed_out"])
        self.assertIn("global scan deadline", reports[1]["warnings"][0])

    def test_policy_blocks_deeper_handler_before_execution(self) -> None:
        policy = ScanPolicy(maximum_probe_level=ProbeLevel.PASSIVE, redaction=RedactionMode.NONE)
        report = scan([ActiveHandler], policy=policy, host_id="test-host")["reports"][0]
        self.assertEqual(report["status"], "blocked_by_policy")

    def test_malformed_handler_result_is_contained(self) -> None:
        report = scan([MalformedHandler], host_id="test-host")["reports"][0]
        self.assertEqual(report["status"], "failed")
        self.assertIn("expected HandlerReport", report["warnings"][0])

    def test_generated_inventory_validates(self) -> None:
        validate_inventory(scan([GoodHandler], host_id="test-host"))

    def test_duplicate_stable_ids_are_rejected(self) -> None:
        document = scan([GoodHandler], host_id="test-host")
        duplicate = dict(document["reports"][0]["devices"][0])
        document["reports"][0]["devices"].append(duplicate)
        with self.assertRaises(SchemaError):
            validate_inventory(document)

    def test_inconsistent_coverage_is_rejected(self) -> None:
        document = scan([GoodHandler], host_id="test-host")
        document["reports"][0]["coverage"]["device_count"] = 99
        with self.assertRaises(SchemaError):
            validate_inventory(document)


if __name__ == "__main__":
    unittest.main()
