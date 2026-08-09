from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import hwprobe.io
from hwprobe.io import begin_io_audit, describe_binary, finish_io_audit, iter_paths, link_name, read_text


class IoAuditTests(unittest.TestCase):
    def test_success_and_missing_reads_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            present = Path(directory) / "present"
            present.write_text("value\n", encoding="utf-8")
            begin_io_audit()
            self.assertEqual(read_text(present), "value")
            self.assertIsNone(read_text(Path(directory) / "missing"))
            audit = finish_io_audit().summary()
        self.assertEqual(audit["attempted_reads"], 2)
        self.assertEqual(audit["successful_reads"], 1)
        self.assertEqual(audit["not_found"], 1)

    def test_passive_transport_has_no_write_open_flags(self) -> None:
        source = inspect.getsource(hwprobe.io)
        self.assertNotIn("O_WRONLY", source)
        self.assertNotIn("O_RDWR", source)

    def test_permission_denial_is_distinct(self) -> None:
        begin_io_audit()
        with patch("hwprobe.io.os.open", side_effect=PermissionError):
            self.assertIsNone(read_text(Path("/denied")))
        audit = finish_io_audit()
        self.assertEqual(audit.permission_denied, 1)
        self.assertEqual(audit.observations[0].status, "permission_denied")

    def test_text_and_binary_size_limits_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large"
            path.write_bytes(b"12345678")
            begin_io_audit()
            self.assertIsNone(read_text(path, limit=2))
            self.assertEqual(describe_binary(path, hash_limit=2)["note"], "digest size limit exceeded")
            audit = finish_io_audit()
        self.assertEqual(audit.size_limit_exceeded, 2)

    def test_directory_permission_denial_is_recorded(self) -> None:
        begin_io_audit()
        with patch.object(Path, "iterdir", side_effect=PermissionError):
            self.assertEqual(iter_paths(Path("/denied")), [])
        audit = finish_io_audit()
        self.assertEqual(audit.permission_denied, 1)

    def test_broken_symlink_target_is_still_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / "driver"
            link.symlink_to("../missing-driver")
            begin_io_audit()
            self.assertEqual(link_name(link), "missing-driver")
            audit = finish_io_audit()
        self.assertEqual(audit.successful_reads, 1)
        self.assertEqual(audit.observations[0].operation, "read_link")


if __name__ == "__main__":
    unittest.main()
