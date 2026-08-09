from __future__ import annotations

import subprocess
import tempfile
import unittest
import hashlib
from pathlib import Path

from tools.build_zipapp import build


class ZipappTests(unittest.TestCase):
    def test_portable_scanner_lists_handlers_and_scans(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application = build(Path(directory) / "hwprobe.pyz")
            handlers = subprocess.run(
                [str(application), "handlers"],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertIn("linux-cpu", handlers.stdout)
            inventory = Path(directory) / "inventory.json"
            subprocess.run(
                [
                    str(application),
                    "scan",
                    "--handler",
                    "linux-cpu",
                    "--output",
                    str(inventory),
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            validation = subprocess.run(
                [str(application), "validate", str(inventory)],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(validation.stdout.strip(), "valid inventory")

    def test_build_is_reproducible_and_excludes_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first = build(Path(directory) / "first.pyz")
            second = build(Path(directory) / "second.pyz")
            self.assertEqual(
                hashlib.sha256(first.read_bytes()).hexdigest(),
                hashlib.sha256(second.read_bytes()).hexdigest(),
            )
            self.assertNotIn(b"__pycache__", first.read_bytes())


if __name__ == "__main__":
    unittest.main()
