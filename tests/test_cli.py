from __future__ import annotations

import unittest

from hwprobe.cli import select_handlers


class CliTests(unittest.TestCase):
    def test_handler_include_preserves_requested_order(self) -> None:
        selected = select_handlers(["linux-usb", "linux-cpu"], [])
        self.assertEqual([handler.name for handler in selected], ["linux-usb", "linux-cpu"])

    def test_handler_exclusion(self) -> None:
        selected = select_handlers([], ["linux-usb"])
        self.assertNotIn("linux-usb", [handler.name for handler in selected])

    def test_unknown_handler_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            select_handlers(["not-real"], [])


if __name__ == "__main__":
    unittest.main()
