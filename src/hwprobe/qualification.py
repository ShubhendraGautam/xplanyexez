from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hwprobe.handlers import HANDLERS
from hwprobe.provenance import ContentAddressedStore, EvidenceError, verify_evidence
from hwprobe.schema import SchemaError, validate_inventory


@dataclass(slots=True)
class QualificationCheck:
    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, str | bool]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


def _environment_kind(document: dict[str, Any]) -> tuple[str, str]:
    run = document["run"]
    kernel = run.get("kernel", "").lower()
    if "microsoft" in kernel or "wsl" in kernel:
        return "virtualized", "kernel identifies Windows Subsystem for Linux"
    for report in document["reports"]:
        if report["category"] != "cpu":
            continue
        for device in report["devices"]:
            flags = str(device.get("facts", {}).get("flags", "")).split()
            if "hypervisor" in flags:
                return "virtualized", "CPU feature report advertises a hypervisor"
    return "physical-candidate", "no virtualization marker found; operator attestation is still required"


def qualify_inventory(
    document: dict[str, Any],
    *,
    evidence_dir: Path | None = None,
) -> dict[str, Any]:
    checks: list[QualificationCheck] = []
    try:
        validate_inventory(document)
        checks.append(QualificationCheck("schema", True, f"schema {document['schema_version']} is valid"))
    except SchemaError as exc:
        return {
            "qualified": False,
            "qualification_scope": "software",
            "environment": {"kind": "unknown", "detail": "schema invalid"},
            "checks": [QualificationCheck("schema", False, str(exc)).to_dict()],
        }

    expected_handlers = [handler_type.name for handler_type in HANDLERS]
    actual_handlers = [report["handler"] for report in document["reports"]]
    checks.append(
        QualificationCheck(
            "handler-set",
            actual_handlers == expected_handlers,
            f"expected {len(expected_handlers)} handlers; received {len(actual_handlers)}",
        )
    )

    terminal_failures = [
        report["handler"]
        for report in document["reports"]
        if report["status"] in {"failed", "timed_out", "blocked_by_policy"}
    ]
    checks.append(
        QualificationCheck(
            "handler-completion",
            not terminal_failures,
            "all handlers completed or reported partial coverage"
            if not terminal_failures
            else f"terminal failures: {', '.join(terminal_failures)}",
        )
    )

    unjustified_partial = [
        report["handler"]
        for report in document["reports"]
        if report["status"] == "partial"
        and not report["warnings"]
        and not report["coverage"]["io"].get("permission_denied", 0)
        and not report["coverage"]["io"].get("io_errors", 0)
    ]
    checks.append(
        QualificationCheck(
            "partial-coverage-explanations",
            not unjustified_partial,
            "every partial report has a warning or audited access failure"
            if not unjustified_partial
            else f"unexplained partial reports: {', '.join(unjustified_partial)}",
        )
    )

    store_enabled = bool(document["run"]["evidence_store"].get("enabled"))
    if store_enabled and evidence_dir is not None:
        try:
            result = verify_evidence(document, ContentAddressedStore(evidence_dir))
            evidence_check = QualificationCheck(
                "evidence-store",
                True,
                f"verified {result['objects_verified']} objects and {result['bytes_verified']} bytes",
            )
        except EvidenceError as exc:
            evidence_check = QualificationCheck("evidence-store", False, str(exc))
    elif store_enabled:
        evidence_check = QualificationCheck(
            "evidence-store",
            False,
            "inventory declares a store but --evidence-dir was not provided",
        )
    else:
        evidence_check = QualificationCheck(
            "evidence-store",
            False,
            "qualification scans must enable the private evidence store",
        )
    checks.append(evidence_check)

    kind, environment_detail = _environment_kind(document)
    software_qualified = all(check.passed for check in checks)
    return {
        "qualified": software_qualified,
        "qualification_scope": "software",
        "environment": {
            "kind": kind,
            "detail": environment_detail,
            "counts_toward_physical_m1_gate": False,
            "operator_attestation_required": True,
        },
        "run_id": document["run"]["run_id"],
        "host_id": document["run"]["host_id"],
        "checks": [check.to_dict() for check in checks],
    }
