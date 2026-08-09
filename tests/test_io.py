from __future__ import annotations

import tempfile
import unittest
import inspect
from pathlib import Path

import hwprobe.io
from hwprobe.io import begin_io_audit, finish_io_audit, read_text


class IoAuditTests(unittest.TestCase):
    def test_success_and_missing_reads_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            present = Path(directory) / "present"
            present.write_text("value\n", encoding="utf-8")
            begin_io_audit()
            self.assertEqual(read_text(present), "value")
            self.assertIsNone(read_text(Path(directory) / "missing"))
            audit = finish_io_audit()
        self.assertEqual(audit["attempted_reads"], 2)
        self.assertEqual(audit["successful_reads"], 1)
        self.assertEqual(audit["not_found"], 1)

    def test_passive_transport_has_no_write_open_flags(self) -> None:
        source = inspect.getsource(hwprobe.io)
        self.assertNotIn("O_WRONLY", source)
        self.assertNotIn("O_RDWR", source)


if __name__ == "__main__":
    unittest.main()
