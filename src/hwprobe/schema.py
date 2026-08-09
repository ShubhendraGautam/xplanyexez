from __future__ import annotations

from typing import Any


class SchemaError(ValueError):
    pass


def _require(mapping: dict[str, Any], key: str, expected: type, location: str) -> Any:
    if key not in mapping:
        raise SchemaError(f"{location}: missing required key {key!r}")
    value = mapping[key]
    if not isinstance(value, expected):
        raise SchemaError(f"{location}.{key}: expected {expected.__name__}, got {type(value).__name__}")
    return value


def validate_inventory(document: object) -> None:
    """Validate invariants that JSON Schema alone cannot make convenient to test."""
    if not isinstance(document, dict):
        raise SchemaError("inventory: expected object")
    if document.get("schema_version") != "1.1":
        raise SchemaError("inventory.schema_version: unsupported version")
    run = _require(document, "run", dict, "inventory")
    for key in ("run_id", "started_at_utc", "completed_at_utc", "host_id", "tool"):
        _require(run, key, str if key != "tool" else dict, "inventory.run")
    reports = _require(document, "reports", list, "inventory")
    stable_ids: set[str] = set()
    valid_status = {"complete", "partial", "failed", "timed_out", "blocked_by_policy"}
    for index, report in enumerate(reports):
        location = f"inventory.reports[{index}]"
        if not isinstance(report, dict):
            raise SchemaError(f"{location}: expected object")
        for key, expected in (("handler", str), ("category", str), ("probe_level", int), ("status", str), ("devices", list), ("coverage", dict), ("capabilities", dict)):
            _require(report, key, expected, location)
        if report["status"] not in valid_status:
            raise SchemaError(f"{location}.status: invalid value {report['status']!r}")
        for device_index, device in enumerate(report["devices"]):
            device_location = f"{location}.devices[{device_index}]"
            if not isinstance(device, dict):
                raise SchemaError(f"{device_location}: expected object")
            _require(device, "id", str, device_location)
            stable_id = _require(device, "stable_id", str, device_location)
            if stable_id in stable_ids:
                raise SchemaError(f"{device_location}.stable_id: duplicate ID")
            stable_ids.add(stable_id)
