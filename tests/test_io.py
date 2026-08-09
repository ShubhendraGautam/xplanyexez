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

    def test_read_race_after_open_is_contained(self) -> None:
        begin_io_audit()
        with (
            patch("hwprobe.io.os.open", return_value=123),
            patch("hwprobe.io.os.read", side_effect=FileNotFoundError),
            patch("hwprobe.io.os.close"),
        ):
            self.assertIsNone(read_text(Path("/vanished")))
        audit = finish_io_audit()
        self.assertEqual(audit.not_found, 1)

    def test_directory_hot_unplug_during_iteration_is_contained(self) -> None:
        def vanishing_entries():
            yield Path("/bus/device0")
            raise FileNotFoundError

        begin_io_audit()
        with patch.object(Path, "iterdir", return_value=vanishing_entries()):
            self.assertEqual(iter_paths(Path("/bus")), [])
        audit = finish_io_audit()
        self.assertEqual(audit.not_found, 1)

    def test_symlink_failure_modes_are_distinct(self) -> None:
        cases = (
            (FileNotFoundError(), "not_found"),
            (PermissionError(), "permission_denied"),
            (OSError(), "io_errors"),
        )
        for exception, expected in cases:
            with self.subTest(status=expected):
                begin_io_audit()
                with patch("hwprobe.io.os.readlink", side_effect=exception):
                    self.assertIsNone(link_name(Path("/link")))
                audit = finish_io_audit()
                self.assertEqual(getattr(audit, expected), 1)

    def test_binary_failure_modes_are_distinct(self) -> None:
        cases = (
            (FileNotFoundError(), "not_found"),
            (PermissionError(), "permission_denied"),
            (OSError(), "io_errors"),
        )
        for exception, expected in cases:
            with self.subTest(status=expected):
                begin_io_audit()
                with patch.object(Path, "stat", side_effect=exception):
                    self.assertIsNone(describe_binary(Path("/table")))
                audit = finish_io_audit()
                self.assertEqual(getattr(audit, expected), 1)


if __name__ == "__main__":
    unittest.main()
