from __future__ import annotations

import unittest

from hwprobe.cpuid import CpuidRecord, decode_cpuid, enumerate_cpuid


def registers(text: bytes) -> tuple[int, ...]:
    padded = text.ljust(12, b"\x00")
    return tuple(int.from_bytes(padded[index:index + 4], "little") for index in range(0, 12, 4))


class CpuidTests(unittest.TestCase):
    def test_enumerates_bounded_namespaces_and_structured_subleaves(self) -> None:
        vendor_ebx, vendor_edx, vendor_ecx = registers(b"GenuineIntel")
        hyper_ebx, hyper_ecx, hyper_edx = registers(b"Microsoft Hv")
        replies = {
            (0, 0): (7, vendor_ebx, vendor_ecx, vendor_edx),
            (1, 0): (0x000806A1, 0, 1 << 31, 1 << 25),
            (4, 0): (1, 0, 0, 0),
            (4, 1): (0, 0, 0, 0),
            (7, 0): (1, 1 << 5, 0, 0),
            (7, 1): (0, 0, 0, 0),
            (0x40000000, 0): (0x40000002, hyper_ebx, hyper_ecx, hyper_edx),
            (0x80000000, 0): (0x80000001, 0, 0, 0),
            (0x80000001, 0): (0, 0, 0, 1 << 29),
        }
        seen: list[tuple[int, int]] = []

        def query(leaf: int, subleaf: int):
            seen.append((leaf, subleaf))
            return replies.get((leaf, subleaf), (0, 0, 0, 0))

        records, truncations = enumerate_cpuid(query)
        decoded = decode_cpuid(records)

        self.assertEqual(truncations, ())
        self.assertIn((4, 1), seen)
        self.assertIn((7, 1), seen)
        self.assertIn((0x40000002, 0), seen)
        self.assertNotIn((8, 0), seen)
        self.assertEqual(decoded["vendor_id"], "GenuineIntel")
        self.assertEqual(decoded["hypervisor_vendor_id"], "Microsoft Hv")
        self.assertIn("avx2", decoded["features"])
        self.assertIn("lm", decoded["features"])

    def test_invalid_reported_maximum_is_capped(self) -> None:
        def query(leaf: int, subleaf: int):
            if (leaf, subleaf) == (0, 0):
                return (0xFFFFFFFF, 0, 0, 0)
            if (leaf, subleaf) == (0x80000000, 0):
                return (0, 0, 0, 0)
            return (0, 0, 0, 0)

        records, truncations = enumerate_cpuid(query)
        self.assertLessEqual(len(records), 258)
        self.assertTrue(any("basic namespace" in message for message in truncations))

    def test_decodes_brand_and_signature(self) -> None:
        vendor_ebx, vendor_edx, vendor_ecx = registers(b"AuthenticAMD")
        brand = b"Fixture CPU".ljust(48, b"\x00")
        records = [
            CpuidRecord(0, 0, 1, vendor_ebx, vendor_ecx, vendor_edx),
            CpuidRecord(1, 0, 0x00A20F12, 0, 0, 0),
            CpuidRecord(0x80000000, 0, 0x80000004, 0, 0, 0),
        ]
        for index, leaf in enumerate(range(0x80000002, 0x80000005)):
            chunk = brand[index * 16:(index + 1) * 16]
            values = tuple(int.from_bytes(chunk[offset:offset + 4], "little") for offset in range(0, 16, 4))
            records.append(CpuidRecord(leaf, 0, *values))

        decoded = decode_cpuid(tuple(records))
        self.assertEqual(decoded["vendor_id"], "AuthenticAMD")
        self.assertEqual(decoded["brand"], "Fixture CPU")
        self.assertEqual(decoded["signature"]["stepping"], 2)


if __name__ == "__main__":
    unittest.main()
