from __future__ import annotations

import copy
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
    return _redact(copy.deepcopy(document), keys)
