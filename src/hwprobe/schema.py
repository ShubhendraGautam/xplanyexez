from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID


class SchemaError(ValueError):
    pass


def _require(mapping: dict[str, Any], key: str, expected: type | tuple[type, ...], location: str) -> Any:
    if key not in mapping:
        raise SchemaError(f"{location}: missing required key {key!r}")
    value = mapping[key]
    if not isinstance(value, expected):
        expected_name = (
            " or ".join(item.__name__ for item in expected)
            if isinstance(expected, tuple)
            else expected.__name__
        )
        raise SchemaError(f"{location}.{key}: expected {expected_name}, got {type(value).__name__}")
    return value


def validate_inventory(document: object) -> None:
    """Validate invariants that JSON Schema alone cannot make convenient to test."""
    if not isinstance(document, dict):
        raise SchemaError("inventory: expected object")
    if document.get("schema_version") != "1.2":
        raise SchemaError("inventory.schema_version: unsupported version")
    run = _require(document, "run", dict, "inventory")
    for key in ("run_id", "started_at_utc", "completed_at_utc", "host_id"):
        _require(run, key, str, "inventory.run")
    try:
        UUID(run["run_id"])
    except ValueError as exc:
        raise SchemaError("inventory.run.run_id: invalid UUID") from exc
    try:
        started = datetime.fromisoformat(run["started_at_utc"])
        completed = datetime.fromisoformat(run["completed_at_utc"])
    except ValueError as exc:
        raise SchemaError("inventory.run: invalid ISO-8601 timestamp") from exc
    if started.tzinfo is None or completed.tzinfo is None:
        raise SchemaError("inventory.run: timestamps must include a timezone")
    if completed < started:
        raise SchemaError("inventory.run.completed_at_utc: precedes scan start")
    duration_ms = _require(run, "duration_ms", (int, float), "inventory.run")
    if duration_ms < 0:
        raise SchemaError("inventory.run.duration_ms: cannot be negative")
    tool = _require(run, "tool", dict, "inventory.run")
    _require(tool, "name", str, "inventory.run.tool")
    _require(tool, "version", str, "inventory.run.tool")
    policy = _require(run, "policy", dict, "inventory.run")
    maximum_probe_level = _require(policy, "maximum_probe_level", int, "inventory.run.policy")
    redaction = _require(policy, "redaction", str, "inventory.run.policy")
    if redaction not in {"none", "identifiers", "strict"}:
        raise SchemaError("inventory.run.policy.redaction: invalid mode")
    requested_handlers = _require(run, "requested_handlers", list, "inventory.run")
    effective_probe_level = _require(run, "effective_probe_level", int, "inventory.run")
    evidence_store = _require(run, "evidence_store", dict, "inventory.run")
    _require(evidence_store, "enabled", bool, "inventory.run.evidence_store")
    if evidence_store.get("algorithm") != "sha256":
        raise SchemaError("inventory.run.evidence_store.algorithm: expected sha256")
    reports = _require(document, "reports", list, "inventory")
    stable_ids: set[str] = set()
    handler_names: set[str] = set()
    valid_status = {"complete", "partial", "failed", "timed_out", "blocked_by_policy"}
    valid_observation_status = {
        "success",
        "not_found",
        "permission_denied",
        "io_errors",
        "size_limit_exceeded",
        "redacted",
    }
    for index, report in enumerate(reports):
        location = f"inventory.reports[{index}]"
        if not isinstance(report, dict):
            raise SchemaError(f"{location}: expected object")
        for key, expected in (("handler", str), ("category", str), ("probe_level", int), ("status", str), ("devices", list), ("provenance", list), ("coverage", dict), ("capabilities", dict)):
            _require(report, key, expected, location)
        if report["status"] not in valid_status:
            raise SchemaError(f"{location}.status: invalid value {report['status']!r}")
        if report["handler"] in handler_names:
            raise SchemaError(f"{location}.handler: duplicate handler report")
        handler_names.add(report["handler"])
        if report["probe_level"] < 0 or report["probe_level"] > maximum_probe_level:
            raise SchemaError(f"{location}.probe_level: outside requested policy")
        for observation_index, observation in enumerate(report["provenance"]):
            observation_location = f"{location}.provenance[{observation_index}]"
            if not isinstance(observation, dict):
                raise SchemaError(f"{observation_location}: expected object")
            for key in ("source", "transport", "operation", "status"):
                _require(observation, key, str, observation_location)
            sequence = _require(observation, "sequence", int, observation_location)
            if sequence != observation_index:
                raise SchemaError(f"{observation_location}.sequence: expected {observation_index}")
            duration_us = _require(observation, "duration_us", int, observation_location)
            if duration_us < 0:
                raise SchemaError(f"{observation_location}.duration_us: cannot be negative")
            if observation["status"] not in valid_observation_status:
                raise SchemaError(f"{observation_location}.status: invalid value")
            if observation["status"] == "success":
                digest = _require(observation, "sha256", str, observation_location)
                if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                    raise SchemaError(f"{observation_location}.sha256: invalid digest")
                _require(observation, "size", int, observation_location)
        coverage = report["coverage"]
        if coverage.get("device_count") != len(report["devices"]):
            raise SchemaError(f"{location}.coverage.device_count: does not match devices")
        if coverage.get("evidence_source_count") != len(report.get("evidence", [])):
            raise SchemaError(f"{location}.coverage.evidence_source_count: does not match evidence")
        if coverage.get("warning_count") != len(report.get("warnings", [])):
            raise SchemaError(f"{location}.coverage.warning_count: does not match warnings")
        io_coverage = coverage.get("io", {})
        outcome_total = sum(
            io_coverage.get(key, 0)
            for key in ("successful_reads", "not_found", "permission_denied", "io_errors", "size_limit_exceeded")
        )
        if io_coverage and io_coverage.get("attempted_reads") != outcome_total:
            raise SchemaError(f"{location}.coverage.io: read outcomes do not match attempts")
        if redaction != "strict" and io_coverage.get("observation_count", 0) != len(report["provenance"]):
            raise SchemaError(f"{location}.coverage.io.observation_count: does not match provenance")
        for device_index, device in enumerate(report["devices"]):
            device_location = f"{location}.devices[{device_index}]"
            if not isinstance(device, dict):
                raise SchemaError(f"{device_location}: expected object")
            _require(device, "id", str, device_location)
            stable_id = _require(device, "stable_id", str, device_location)
            if stable_id in stable_ids:
                raise SchemaError(f"{device_location}.stable_id: duplicate ID")
            stable_ids.add(stable_id)
    if requested_handlers != [report["handler"] for report in reports]:
        raise SchemaError("inventory.run.requested_handlers: does not match reports")
    if reports and effective_probe_level != max(report["probe_level"] for report in reports):
        raise SchemaError("inventory.run.effective_probe_level: does not match reports")
