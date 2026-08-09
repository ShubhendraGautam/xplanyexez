from __future__ import annotations

import copy
from pathlib import PurePath
from typing import Any

from hwprobe.policy import RedactionMode


IDENTIFIER_KEYS = {
    "address",
    "board_asset_tag",
    "board_serial",
    "chassis_asset_tag",
    "chassis_serial",
    "hostname",
    "mac",
    "product_serial",
    "product_uuid",
    "serial",
}

STRICT_KEYS = IDENTIFIER_KEYS | {
    "evidence",
    "facts",
    "host_id",
    "name",
    "path",
    "provenance",
}


def _redact(value: Any, keys: set[str], *, parent_key: str | None = None) -> Any:
    if parent_key and parent_key.lower() in keys:
        if isinstance(value, list):
            return []
        if isinstance(value, dict):
            return {}
        return "<redacted>"
    if isinstance(value, dict):
        return {key: _redact(item, keys, parent_key=key) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, keys, parent_key=parent_key) for item in value]
    return value


def redact_inventory(document: dict[str, Any], mode: RedactionMode) -> dict[str, Any]:
    if mode is RedactionMode.NONE:
        return document
    keys = STRICT_KEYS if mode is RedactionMode.STRICT else IDENTIFIER_KEYS
    redacted = _redact(copy.deepcopy(document), keys)
    if mode is RedactionMode.STRICT:
        for report in redacted.get("reports", []):
            report.get("coverage", {})["evidence_source_count"] = 0
            report.get("coverage", {}).get("io", {})["observation_count"] = 0
    else:
        for report in redacted.get("reports", []):
            for observation in report.get("provenance", []):
                basename = PurePath(observation.get("source", "")).name.lower()
                if basename in IDENTIFIER_KEYS:
                    observation["status"] = "redacted"
                    observation["sha256"] = None
                    observation["size"] = None
                    observation["detail"] = "identifier evidence omitted from shared report"
    return redacted
