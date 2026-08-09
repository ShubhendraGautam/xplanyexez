from __future__ import annotations

import ctypes
import mmap
import os
import platform
import struct
import time
from dataclasses import dataclass
from typing import Callable

from hwprobe.io import record_transport_failure, record_transport_success


RegisterTuple = tuple[int, int, int, int]
Query = Callable[[int, int], RegisterTuple]

MAX_NAMESPACE_LEAVES = 0x100
MAX_SUBLEAVES = 64


class CpuidUnavailable(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CpuidRecord:
    leaf: int
    subleaf: int
    eax: int
    ebx: int
    ecx: int
    edx: int

    def to_dict(self) -> dict[str, str]:
        return {
            "leaf": f"0x{self.leaf:08x}",
            "subleaf": f"0x{self.subleaf:08x}",
            "eax": f"0x{self.eax:08x}",
            "ebx": f"0x{self.ebx:08x}",
            "ecx": f"0x{self.ecx:08x}",
            "edx": f"0x{self.edx:08x}",
        }


@dataclass(frozen=True, slots=True)
class CpuidCapture:
    records: tuple[CpuidRecord, ...]
    decoded: dict[str, object]
    evidence: tuple[str, ...]
    truncations: tuple[str, ...]


def _ascii_registers(*values: int) -> str:
    return b"".join(value.to_bytes(4, "little") for value in values).decode(
        "ascii", errors="replace"
    ).rstrip("\x00 ")


def _feature_names(value: int, names: dict[int, str]) -> set[str]:
    return {name for bit, name in names.items() if value & (1 << bit)}


LEAF_1_EDX = {
    0: "fpu", 1: "vme", 2: "de", 3: "pse", 4: "tsc", 5: "msr",
    6: "pae", 7: "mce", 8: "cx8", 9: "apic", 11: "sep", 12: "mtrr",
    13: "pge", 14: "mca", 15: "cmov", 16: "pat", 17: "pse36",
    19: "clflush", 23: "mmx", 24: "fxsr", 25: "sse", 26: "sse2",
    28: "htt",
}
LEAF_1_ECX = {
    0: "sse3", 1: "pclmulqdq", 3: "monitor", 5: "vmx", 6: "smx",
    9: "ssse3", 12: "fma", 13: "cx16", 17: "pcid", 19: "sse4_1",
    20: "sse4_2", 21: "x2apic", 22: "movbe", 23: "popcnt",
    24: "tsc_deadline_timer", 25: "aes", 26: "xsave", 27: "osxsave",
    28: "avx", 29: "f16c", 30: "rdrand", 31: "hypervisor",
}
LEAF_7_EBX = {
    0: "fsgsbase", 3: "bmi1", 5: "avx2", 7: "smep", 8: "bmi2",
    9: "erms", 10: "invpcid", 16: "avx512f", 17: "avx512dq",
    18: "rdseed", 19: "adx", 20: "smap", 23: "clflushopt", 24: "clwb",
    28: "avx512cd", 29: "sha", 30: "avx512bw", 31: "avx512vl",
}
LEAF_7_ECX = {
    0: "prefetchwt1", 1: "avx512_vbmi", 2: "umip", 3: "pku",
    4: "ospke", 5: "waitpkg", 6: "avx512_vbmi2", 8: "gfni", 9: "vaes",
    10: "vpclmulqdq", 11: "avx512_vnni", 12: "avx512_bitalg",
    14: "avx512_vpopcntdq", 22: "rdpid", 25: "cldemote", 27: "movdiri",
    28: "movdir64b", 29: "enqcmd", 30: "sgx_lc", 31: "pks",
}
LEAF_7_EDX = {
    2: "avx512_4vnniw", 3: "avx512_4fmaps", 4: "fsrm",
    8: "avx512_vp2intersect", 10: "md_clear", 14: "serialize",
    15: "hybrid", 16: "tsxldtrk", 18: "pconfig", 20: "cet_ibt",
    22: "amx_bf16", 23: "avx512_fp16", 24: "amx_tile", 25: "amx_int8",
    26: "ibrs_ibpb", 27: "stibp", 28: "l1d_flush",
    29: "arch_capabilities", 30: "core_capabilities", 31: "ssbd",
}
EXTENDED_1_ECX = {
    0: "lahf_lm", 2: "svm", 5: "abm", 6: "sse4a", 7: "misalignsse",
    8: "3dnowprefetch", 9: "osvw", 10: "ibs", 11: "xop", 12: "skinit",
    13: "wdt", 15: "lwp", 16: "fma4", 17: "tce", 19: "nodeid_msr",
    21: "tbm", 22: "topoext", 23: "perfctr_core", 24: "perfctr_nb",
    26: "bpext", 27: "ptsc", 28: "perfctr_llc", 29: "mwaitx",
    30: "addr_mask_ext",
}
EXTENDED_1_EDX = {
    11: "syscall", 20: "nx", 22: "mmxext", 25: "fxsr_opt",
    26: "pdpe1gb", 27: "rdtscp", 29: "lm", 30: "3dnowext", 31: "3dnow",
}


def _bounded_max(root: int, reported: int, truncations: list[str], name: str) -> int:
    if reported < root:
        return root
    limit = root + MAX_NAMESPACE_LEAVES - 1
    if reported > limit:
        truncations.append(
            f"{name} namespace reported maximum 0x{reported:08x}; capped at 0x{limit:08x}"
        )
        return limit
    return reported


def enumerate_cpuid(query: Query) -> tuple[tuple[CpuidRecord, ...], tuple[str, ...]]:
    """Enumerate documented CPUID namespaces without sweeping reserved inputs."""
    values: dict[tuple[int, int], RegisterTuple] = {}
    truncations: list[str] = []

    def capture(leaf: int, subleaf: int = 0) -> RegisterTuple:
        key = (leaf, subleaf)
        if key not in values:
            values[key] = tuple(value & 0xFFFFFFFF for value in query(leaf, subleaf))  # type: ignore[assignment]
        return values[key]

    def enumerate_leaf(leaf: int) -> None:
        first = capture(leaf, 0)
        if leaf in {0x4, 0x8000001D}:
            if first[0] & 0x1F == 0:
                return
            for subleaf in range(1, MAX_SUBLEAVES):
                if capture(leaf, subleaf)[0] & 0x1F == 0:
                    break
            else:
                truncations.append(f"leaf 0x{leaf:08x} cache subleaves reached cap")
        elif leaf in {0x7, 0x14, 0x17, 0x18, 0x1D}:
            maximum = first[0]
            if maximum >= MAX_SUBLEAVES:
                truncations.append(f"leaf 0x{leaf:08x} reported {maximum} subleaves; capped")
            for subleaf in range(1, min(maximum, MAX_SUBLEAVES - 1) + 1):
                capture(leaf, subleaf)
        elif leaf in {0xB, 0x1F}:
            if (first[2] >> 8) & 0xFF == 0:
                return
            for subleaf in range(1, MAX_SUBLEAVES):
                if (capture(leaf, subleaf)[2] >> 8) & 0xFF == 0:
                    break
            else:
                truncations.append(f"leaf 0x{leaf:08x} topology subleaves reached cap")
        elif leaf == 0xD:
            second = capture(leaf, 1)
            state_mask = first[0] | (first[3] << 32) | second[2] | (second[3] << 32)
            for subleaf in range(2, MAX_SUBLEAVES):
                if state_mask & (1 << subleaf):
                    capture(leaf, subleaf)
        elif leaf == 0xF:
            for subleaf in range(1, 32):
                if first[3] & (1 << subleaf):
                    capture(leaf, subleaf)
        elif leaf == 0x10:
            for subleaf in range(1, 32):
                if first[1] & (1 << subleaf):
                    capture(leaf, subleaf)
        elif leaf == 0x12:
            if first[0] & 0x3 == 0:
                return
            capture(leaf, 1)
            for subleaf in range(2, MAX_SUBLEAVES):
                if capture(leaf, subleaf)[0] & 0xF == 0:
                    break
            else:
                truncations.append("leaf 0x00000012 EPC subleaves reached cap")

    basic_root = capture(0, 0)
    basic_max = _bounded_max(0, basic_root[0], truncations, "basic")
    for leaf in range(1, basic_max + 1):
        enumerate_leaf(leaf)

    extended_root = capture(0x80000000, 0)
    extended_max = _bounded_max(0x80000000, extended_root[0], truncations, "extended")
    for leaf in range(0x80000001, extended_max + 1):
        enumerate_leaf(leaf)

    leaf_one = values.get((1, 0))
    if leaf_one is not None and leaf_one[2] & (1 << 31):
        hypervisor_root = capture(0x40000000, 0)
        hypervisor_max = _bounded_max(
            0x40000000, hypervisor_root[0], truncations, "hypervisor"
        )
        for leaf in range(0x40000001, hypervisor_max + 1):
            capture(leaf, 0)

    records = tuple(
        CpuidRecord(leaf, subleaf, *registers)
        for (leaf, subleaf), registers in sorted(values.items())
    )
    return records, tuple(truncations)


def decode_cpuid(records: tuple[CpuidRecord, ...]) -> dict[str, object]:
    by_input = {(record.leaf, record.subleaf): record for record in records}
    decoded: dict[str, object] = {"record_count": len(records)}
    features: set[str] = set()

    basic = by_input.get((0, 0))
    if basic is not None:
        decoded["maximum_basic_leaf"] = f"0x{basic.eax:08x}"
        decoded["vendor_id"] = _ascii_registers(basic.ebx, basic.edx, basic.ecx)

    leaf_one = by_input.get((1, 0))
    if leaf_one is not None:
        base_family = (leaf_one.eax >> 8) & 0xF
        base_model = (leaf_one.eax >> 4) & 0xF
        family = base_family + ((leaf_one.eax >> 20) & 0xFF) if base_family == 0xF else base_family
        model = base_model | (((leaf_one.eax >> 16) & 0xF) << 4) if base_family in {0x6, 0xF} else base_model
        decoded["signature"] = {
            "raw": f"0x{leaf_one.eax:08x}",
            "family": family,
            "model": model,
            "stepping": leaf_one.eax & 0xF,
        }
        features.update(_feature_names(leaf_one.edx, LEAF_1_EDX))
        features.update(_feature_names(leaf_one.ecx, LEAF_1_ECX))

    leaf_seven = by_input.get((7, 0))
    if leaf_seven is not None:
        features.update(_feature_names(leaf_seven.ebx, LEAF_7_EBX))
        features.update(_feature_names(leaf_seven.ecx, LEAF_7_ECX))
        features.update(_feature_names(leaf_seven.edx, LEAF_7_EDX))

    extended = by_input.get((0x80000000, 0))
    if extended is not None:
        decoded["maximum_extended_leaf"] = f"0x{extended.eax:08x}"
    extended_one = by_input.get((0x80000001, 0))
    if extended_one is not None:
        features.update(_feature_names(extended_one.ecx, EXTENDED_1_ECX))
        features.update(_feature_names(extended_one.edx, EXTENDED_1_EDX))

    brand_records = [by_input.get((leaf, 0)) for leaf in range(0x80000002, 0x80000005)]
    if all(record is not None for record in brand_records):
        decoded["brand"] = "".join(
            _ascii_registers(record.eax, record.ebx, record.ecx, record.edx)
            for record in brand_records
            if record is not None
        ).strip()

    hypervisor = by_input.get((0x40000000, 0))
    if hypervisor is not None:
        decoded["maximum_hypervisor_leaf"] = f"0x{hypervisor.eax:08x}"
        decoded["hypervisor_vendor_id"] = _ascii_registers(
            hypervisor.ebx, hypervisor.ecx, hypervisor.edx
        )

    decoded["features"] = sorted(features)
    return decoded


class NativeCpuidTransport:
    """Small x86-64 userspace CPUID mechanism with per-CPU affinity."""

    _CODE = bytes.fromhex(
        "53"          # push rbx
        "4989d0"      # mov r8, rdx
        "89f8"        # mov eax, edi
        "89f1"        # mov ecx, esi
        "0fa2"        # cpuid
        "418900"      # mov [r8], eax
        "41895804"    # mov [r8+4], ebx
        "41894808"    # mov [r8+8], ecx
        "4189500c"    # mov [r8+12], edx
        "5b"          # pop rbx
        "c3"          # ret
    )

    def __init__(self) -> None:
        machine = platform.machine().lower()
        if machine not in {"x86_64", "amd64"}:
            raise CpuidUnavailable(f"native CPUID transport does not support {machine or 'unknown'}")
        if not hasattr(os, "sched_getaffinity") or not hasattr(os, "sched_setaffinity"):
            raise CpuidUnavailable("CPU affinity APIs are unavailable")
        try:
            page_size = mmap.PAGESIZE
            self._mapping = mmap.mmap(
                -1,
                page_size,
                flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE,
            )
            self._mapping.write(self._CODE)
            address = ctypes.addressof(ctypes.c_char.from_buffer(self._mapping))
            libc = ctypes.CDLL(None, use_errno=True)
            if libc.mprotect(
                ctypes.c_void_p(address),
                ctypes.c_size_t(page_size),
                mmap.PROT_READ | mmap.PROT_EXEC,
            ) != 0:
                error = ctypes.get_errno()
                self._mapping.close()
                raise OSError(error, os.strerror(error))
            function_type = ctypes.CFUNCTYPE(
                None,
                ctypes.c_uint32,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            )
            self._function = function_type(address)
        except (AttributeError, OSError, ValueError) as exc:
            raise CpuidUnavailable(f"cannot create executable CPUID transport: {exc}") from exc

    def _query(self, leaf: int, subleaf: int) -> RegisterTuple:
        output = (ctypes.c_uint32 * 4)()
        self._function(leaf, subleaf, output)
        return tuple(int(value) for value in output)  # type: ignore[return-value]

    def capture(self, cpu_id: int) -> CpuidCapture:
        original_affinity = os.sched_getaffinity(0)
        if cpu_id not in original_affinity:
            raise CpuidUnavailable(f"logical CPU {cpu_id} is outside process affinity")
        evidence: list[str] = []

        def query(leaf: int, subleaf: int) -> RegisterTuple:
            source = f"cpuid://cpu/{cpu_id}/leaf/{leaf:08x}/subleaf/{subleaf:08x}"
            started_ns = time.monotonic_ns()
            try:
                registers = self._query(leaf, subleaf)
            except Exception as exc:
                record_transport_failure(
                    source,
                    transport="x86-cpuid",
                    operation="execute_cpuid",
                    started_ns=started_ns,
                    detail=type(exc).__name__,
                )
                raise
            raw = struct.pack("<IIIIII", leaf, subleaf, *registers)
            record_transport_success(
                source,
                transport="x86-cpuid",
                operation="execute_cpuid",
                data=raw,
                media_type="application/vnd.xplanyexez.cpuid-registers",
                started_ns=started_ns,
            )
            evidence.append(source)
            return registers

        try:
            os.sched_setaffinity(0, {cpu_id})
            records, truncations = enumerate_cpuid(query)
        except OSError as exc:
            raise CpuidUnavailable(f"cannot bind to logical CPU {cpu_id}: {exc}") from exc
        finally:
            os.sched_setaffinity(0, original_affinity)
        return CpuidCapture(records, decode_cpuid(records), tuple(evidence), truncations)
