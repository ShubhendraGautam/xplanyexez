from __future__ import annotations

import multiprocessing
import platform
import socket
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from multiprocessing.connection import Connection
from typing import Any, Iterable

from hwprobe import __version__
from hwprobe.handlers import HANDLERS
from hwprobe.handlers.base import Handler
from hwprobe.identity import assign_stable_id, stable_host_id
from hwprobe.io import IoAudit, begin_io_audit, finish_io_audit
from hwprobe.model import Device, HandlerReport, HandlerStatus, ProbeLevel
from hwprobe.policy import ScanPolicy
from hwprobe.provenance import ContentAddressedStore, write_private_manifest
from hwprobe.redaction import redact_inventory
from hwprobe.schema import validate_inventory


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class ProbeExecution:
    result: object
    audit: IoAudit


def _probe_worker(handler_type: type[Handler], connection: Connection) -> None:
    begin_io_audit()
    try:
        result = handler_type().probe()
        connection.send(("report", result, finish_io_audit()))
    except BaseException as exc:
        connection.send(("error", type(exc).__name__, str(exc), finish_io_audit()))
    finally:
        connection.close()


def _failed_report(handler: Handler, status: HandlerStatus, warning: str) -> HandlerReport:
    return HandlerReport(
        handler.name,
        handler.category,
        ProbeLevel.TOPOLOGY,
        warnings=[warning],
        status=status.value,
    )


def _run_isolated(handler_type: type[Handler], timeout: float) -> ProbeExecution:
    handler = handler_type()
    context = multiprocessing.get_context("fork")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(target=_probe_worker, args=(handler_type, child), daemon=True)
    process.start()
    child.close()
    try:
        if not parent.poll(timeout):
            process.terminate()
            process.join(1.0)
            if process.is_alive():
                process.kill()
                process.join(1.0)
            return ProbeExecution(
                _failed_report(handler, HandlerStatus.TIMED_OUT, f"handler exceeded {timeout:g}s deadline"),
                IoAudit(),
            )
        message = parent.recv()
        if message[0] == "error":
            return ProbeExecution(
                _failed_report(handler, HandlerStatus.FAILED, f"handler failed: {message[1]}: {message[2]}"),
                message[3],
            )
        return ProbeExecution(message[1], message[2])
    except EOFError:
        return ProbeExecution(
            _failed_report(handler, HandlerStatus.FAILED, f"handler worker exited with code {process.exitcode}"),
            IoAudit(),
        )
    finally:
        parent.close()
        process.join(1.0)
        if process.is_alive():
            process.terminate()
            process.join(1.0)


def _run_inline(handler_type: type[Handler]) -> ProbeExecution:
    handler = handler_type()
    begin_io_audit()
    try:
        result = handler.probe()
        return ProbeExecution(result, finish_io_audit())
    except Exception as exc:
        return ProbeExecution(
            _failed_report(handler, HandlerStatus.FAILED, f"handler failed: {type(exc).__name__}: {exc}"),
            finish_io_audit(),
        )


def _validate_handler_result(handler: Handler, result: object) -> HandlerReport:
    if not isinstance(result, HandlerReport):
        return _failed_report(
            handler,
            HandlerStatus.FAILED,
            f"handler returned {type(result).__name__}, expected HandlerReport",
        )
    if result.handler != handler.name or result.category != handler.category:
        return _failed_report(
            handler,
            HandlerStatus.FAILED,
            "handler report identity does not match its registration",
        )
    try:
        ProbeLevel(result.probe_level)
    except ValueError:
        return _failed_report(
            handler,
            HandlerStatus.FAILED,
            f"handler returned invalid probe level {result.probe_level!r}",
        )
    if any(not isinstance(device, Device) or not isinstance(device.id, str) for device in result.devices):
        return _failed_report(
            handler,
            HandlerStatus.FAILED,
            "handler returned an invalid device record",
        )
    return result


def scan(
    handler_types: Iterable[type[Handler]] = HANDLERS,
    *,
    policy: ScanPolicy | None = None,
    host_id: str | None = None,
    evidence_store: ContentAddressedStore | None = None,
) -> dict[str, Any]:
    policy = policy or ScanPolicy()
    handler_types = tuple(handler_types)
    started_wall = _timestamp()
    started_monotonic = time.monotonic()
    scan_deadline = started_monotonic + policy.scan_timeout_seconds
    resolved_host_id = host_id or stable_host_id()
    reports: list[dict[str, Any]] = []
    effective_probe_level = ProbeLevel.TOPOLOGY
    run_id = str(uuid.uuid4())

    for handler_type in handler_types:
        handler = handler_type()
        started = time.monotonic()
        remaining = scan_deadline - started
        if remaining <= 0:
            execution = ProbeExecution(
                _failed_report(
                    handler,
                    HandlerStatus.TIMED_OUT,
                    f"global scan deadline of {policy.scan_timeout_seconds:g}s was exhausted",
                ),
                IoAudit(),
            )
        elif handler.default_probe_level > policy.maximum_probe_level:
            execution = ProbeExecution(
                _failed_report(
                    handler,
                    HandlerStatus.BLOCKED_BY_POLICY,
                    f"handler requires probe level {int(handler.default_probe_level)}",
                ),
                IoAudit(),
            )
        elif policy.isolate_handlers:
            timeout = min(policy.handler_timeout_seconds, handler.default_timeout_seconds, remaining)
            execution = _run_isolated(handler_type, timeout)
        else:
            execution = _run_inline(handler_type)
        report = _validate_handler_result(handler, execution.result)
        report.duration_ms = round((time.monotonic() - started) * 1000, 3)
        report.evidence = sorted(set(report.evidence))
        report.provenance = [observation.to_dict() for observation in execution.audit.observations]
        report.capabilities = handler_type.capabilities()
        if report.status == HandlerStatus.COMPLETE.value and report.warnings:
            report.status = HandlerStatus.PARTIAL.value
        io_coverage = execution.audit.summary()
        report.coverage = {
            "device_count": len(report.devices),
            "evidence_source_count": len(report.evidence),
            "warning_count": len(report.warnings),
            "claim": "best-effort",
            "io": io_coverage,
        }
        inaccessible = io_coverage.get("permission_denied", 0) + io_coverage.get("io_errors", 0)
        if report.status == HandlerStatus.COMPLETE.value and inaccessible:
            report.status = HandlerStatus.PARTIAL.value
        for device in report.devices:
            assign_stable_id(device, host_id=resolved_host_id, handler=handler.name, category=handler.category)
        if evidence_store is not None:
            evidence_store.put_audit(execution.audit)
        effective_probe_level = max(effective_probe_level, ProbeLevel(report.probe_level))
        reports.append(report.to_dict())

    document = {
        "schema_version": "1.2",
        "run": {
            "run_id": run_id,
            "started_at_utc": started_wall,
            "completed_at_utc": _timestamp(),
            "duration_ms": round((time.monotonic() - started_monotonic) * 1000, 3),
            "host_id": resolved_host_id,
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "kernel": platform.release(),
            "machine": platform.machine(),
            "tool": {"name": "xplanyexez-hwprobe", "version": __version__},
            "policy": policy.to_dict(),
            "requested_handlers": [handler_type.name for handler_type in handler_types],
            "effective_probe_level": int(effective_probe_level),
            "evidence_store": {
                "enabled": evidence_store is not None,
                **(evidence_store.stats.to_dict() if evidence_store is not None else {"algorithm": "sha256"}),
            },
        },
        "reports": reports,
    }
    validate_inventory(document)
    if evidence_store is not None:
        write_private_manifest(document, evidence_store)
    redacted = redact_inventory(document, policy.redaction)
    validate_inventory(redacted)
    return redacted
