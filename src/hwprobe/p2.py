from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol
from uuid import UUID

from hwprobe.provenance import ContentAddressedStore


P2_MANIFEST_SCHEMA = "xplanyexez-p2-manifest/v1"
P2_AUTHORIZATION_SCHEMA = "xplanyexez-p2-authorization/v1"
MAX_P2_TIMEOUT_SECONDS = 30.0
MAX_P2_RESPONSE_BYTES = 1024 * 1024
P2_SIGNATURE_KDF_ITERATIONS = 600_000
MAX_P2_AUTHORIZATION_AGE = timedelta(hours=24)
P2_DATA_CLASSES = frozenset({"hardware-metadata", "hardware-identifiers"})

P2_DISCLAIMER = """P2 ACTIVE HARDWARE PROBE — OWNERSHIP AND RESEARCH ATTESTATION

This operation will transmit a reviewed, deterministic command to the exact
hardware target named in the experiment manifest. A command intended only to
read information can still clear status, consume data, wake or reset hardware,
start DMA or radio transmission, corrupt data, void a warranty, or damage a
device or connected system.

By signing, the operator attests that:
1. the operator is the legal owner of every hardware target in the manifest;
2. the operator is qualified to perform and recover this experiment;
3. the experiment is solely for lawful research and study, with no ulterior,
   unauthorized, harmful, deceptive, or unlawful purpose;
4. all required licences, spectrum rights, third-party consents, and facility
   permissions have been obtained; and
5. the operator accepts responsibility for device, data, service, safety, and
   legal consequences.

This self-attestation records consent and accountability. It does not verify
identity, ownership, qualifications, or legal authority, and it does not make an
otherwise unlawful operation lawful. Stop if any statement is untrue.
"""

P2_ATTESTATION = (
    "I attest that I am the legal owner of every hardware target identified by "
    "this manifest; I am qualified to perform and recover this P2 experiment; "
    "I will use it solely for lawful research and study and not for any ulterior, "
    "unauthorized, harmful, deceptive, or unlawful purpose; I have obtained every "
    "required licence, spectrum right, consent, and permission; and I accept "
    "responsibility for all resulting consequences."
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")


class P2Error(ValueError):
    pass


class P2Transport(Protocol):
    """Code-reviewed transport; arbitrary byte transports must not implement this API."""

    name: str
    allowed_commands: frozenset[str]

    def serialize(self, command: str, parameters: Mapping[str, object]) -> bytes:
        """Return the allowlisted deterministic request for this named command."""

    def exchange(
        self,
        target: Mapping[str, object],
        request: bytes,
        *,
        timeout_seconds: float,
        response_limit_bytes: int,
    ) -> bytes:
        """Transmit exactly request and return at most response_limit_bytes."""


@dataclass(frozen=True, slots=True)
class P2RunResult:
    experiment_id: str
    request_sha256: str
    response_sha256: str
    response_size: int
    trace_path: Path


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(value: datetime | None = None) -> str:
    return (value or _utc_now()).isoformat()


def _parse_timestamp(value: object, location: str) -> datetime:
    if not isinstance(value, str):
        raise P2Error(f"{location}: expected ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise P2Error(f"{location}: invalid ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise P2Error(f"{location}: timezone is required")
    return parsed.astimezone(timezone.utc)


def _require(
    mapping: Mapping[str, Any],
    key: str,
    expected: type | tuple[type, ...],
    location: str,
) -> Any:
    if key not in mapping:
        raise P2Error(f"{location}: missing {key!r}")
    value = mapping[key]
    if not isinstance(value, expected):
        expected_name = (
            " or ".join(item.__name__ for item in expected)
            if isinstance(expected, tuple)
            else expected.__name__
        )
        raise P2Error(f"{location}.{key}: expected {expected_name}")
    return value


def _require_nonempty_string(mapping: Mapping[str, Any], key: str, location: str) -> str:
    value = _require(mapping, key, str, location).strip()
    if not value:
        raise P2Error(f"{location}.{key}: cannot be empty")
    return value


def _require_string_list(mapping: Mapping[str, Any], key: str, location: str) -> list[str]:
    value = _require(mapping, key, list, location)
    if not value or any(not isinstance(item, str) or not item.strip() for item in value):
        raise P2Error(f"{location}.{key}: expected a non-empty list of strings")
    return value


def canonical_json(document: Mapping[str, Any]) -> bytes:
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def document_sha256(document: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(document)).hexdigest()


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"invalid JSON number {value}")


def load_json_object(path: Path, *, kind: str) -> dict[str, Any]:
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"),
            parse_constant=_reject_json_constant,
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise P2Error(f"cannot read {kind} {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise P2Error(f"{kind}: expected a JSON object")
    return document


def _reject_placeholders(value: object, location: str = "manifest") -> None:
    if isinstance(value, str) and value.startswith("REPLACE"):
        raise P2Error(f"{location}: unresolved template placeholder")
    if isinstance(value, dict):
        for key, item in value.items():
            _reject_placeholders(item, f"{location}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_placeholders(item, f"{location}[{index}]")


def validate_manifest(document: Mapping[str, Any], *, now: datetime | None = None) -> None:
    location = "manifest"
    _reject_placeholders(document)
    if document.get("schema_version") != P2_MANIFEST_SCHEMA:
        raise P2Error(f"{location}.schema_version: expected {P2_MANIFEST_SCHEMA!r}")
    experiment_id = _require_nonempty_string(document, "experiment_id", location)
    try:
        UUID(experiment_id)
    except ValueError as exc:
        raise P2Error("manifest.experiment_id: expected UUID") from exc
    _require_nonempty_string(document, "title", location)
    if document.get("purpose") != "research-and-study":
        raise P2Error("manifest.purpose: must be 'research-and-study'")
    if document.get("probe_level") != 2:
        raise P2Error("manifest.probe_level: P2 runner accepts only level 2")
    current = (now or _utc_now()).astimezone(timezone.utc)
    expires = _parse_timestamp(document.get("authorization_expires_at_utc"), "manifest.authorization_expires_at_utc")
    if expires <= current:
        raise P2Error("manifest.authorization_expires_at_utc: authorization window has expired")
    if expires - current > MAX_P2_AUTHORIZATION_AGE:
        raise P2Error("manifest.authorization_expires_at_utc: must be within 24 hours")

    target = _require(document, "target", dict, location)
    for key in ("id", "description", "owner_name", "interface"):
        _require_nonempty_string(target, key, "manifest.target")
    if target.get("remote") is not False:
        raise P2Error("manifest.target.remote: P2 supports only a local physical target")
    if target.get("shared") is not False:
        raise P2Error("manifest.target.shared: shared targets are prohibited")
    if target.get("production") is not False:
        raise P2Error("manifest.target.production: production targets are prohibited")
    if target.get("life_safety") is not False:
        raise P2Error("manifest.target.life_safety: life-safety targets are prohibited")

    operation = _require(document, "operation", dict, location)
    for key in ("adapter", "command"):
        _require_nonempty_string(operation, key, "manifest.operation")
    _require(operation, "parameters", dict, "manifest.operation")
    request_digest = _require_nonempty_string(operation, "request_sha256", "manifest.operation")
    if not _SHA256_RE.fullmatch(request_digest):
        raise P2Error("manifest.operation.request_sha256: expected lowercase SHA-256")
    if request_digest == "0" * 64:
        raise P2Error("manifest.operation.request_sha256: unresolved template digest")
    timeout = _require(operation, "timeout_seconds", (int, float), "manifest.operation")
    if isinstance(timeout, bool) or not 0 < timeout <= MAX_P2_TIMEOUT_SECONDS:
        raise P2Error(f"manifest.operation.timeout_seconds: must be > 0 and <= {MAX_P2_TIMEOUT_SECONDS:g}")
    response_limit = _require(operation, "response_limit_bytes", int, "manifest.operation")
    if isinstance(response_limit, bool) or not 0 < response_limit <= MAX_P2_RESPONSE_BYTES:
        raise P2Error(
            f"manifest.operation.response_limit_bytes: must be > 0 and <= {MAX_P2_RESPONSE_BYTES}"
        )
    if operation.get("max_attempts") != 1:
        raise P2Error("manifest.operation.max_attempts: initial P2 policy requires exactly one attempt")

    _require_string_list(document, "documented_side_effects", location)
    _require_string_list(document, "maximum_credible_harm", location)
    _require_string_list(document, "recovery_plan", location)
    data_classes = _require_string_list(document, "data_classes", location)
    unsupported_data = sorted(set(data_classes) - P2_DATA_CLASSES)
    if unsupported_data:
        raise P2Error(
            "manifest.data_classes: initial P2 policy does not permit " + ", ".join(unsupported_data)
        )
    if document.get("rf_transmission_possible") not in {True, False}:
        raise P2Error("manifest.rf_transmission_possible: expected boolean")
    if document.get("rf_transmission_possible") and not document.get("rf_authorization_reference"):
        raise P2Error("manifest.rf_authorization_reference: required when RF transmission is possible")


def signing_challenge(manifest: Mapping[str, Any], operator_name: str) -> str:
    return f"SIGN {document_sha256(manifest)[:16]} AS {operator_name}"


def create_authorization(
    manifest: Mapping[str, Any],
    *,
    operator_name: str,
    signature_text: str,
    signing_secret: str,
    signed_at: datetime | None = None,
) -> dict[str, Any]:
    validate_manifest(manifest, now=signed_at)
    operator_name = operator_name.strip()
    if not operator_name:
        raise P2Error("operator name cannot be empty")
    owner_name = str(manifest["target"]["owner_name"]).strip()
    if operator_name != owner_name:
        raise P2Error("operator name must exactly match manifest.target.owner_name")
    expected = signing_challenge(manifest, operator_name)
    if signature_text != expected:
        raise P2Error("typed signature did not match the displayed signing challenge")
    if len(signing_secret) < 12:
        raise P2Error("signing passphrase must contain at least 12 characters")
    salt = secrets.token_bytes(16)
    authorization: dict[str, Any] = {
        "schema_version": P2_AUTHORIZATION_SCHEMA,
        "manifest_sha256": document_sha256(manifest),
        "experiment_id": manifest["experiment_id"],
        "target_id": manifest["target"]["id"],
        "operator_name": operator_name,
        "signed_at_utc": _timestamp(signed_at),
        "expires_at_utc": manifest["authorization_expires_at_utc"],
        "signature_method": "typed-name+hmac-sha256/pbkdf2-v1",
        "signature_text": signature_text,
        "attestation": P2_ATTESTATION,
        "signature_kdf": {
            "name": "pbkdf2-hmac-sha256",
            "iterations": P2_SIGNATURE_KDF_ITERATIONS,
            "salt_hex": salt.hex(),
        },
    }
    key = hashlib.pbkdf2_hmac(
        "sha256",
        signing_secret.encode("utf-8"),
        salt,
        P2_SIGNATURE_KDF_ITERATIONS,
    )
    authorization["signature_hmac_sha256"] = hmac.new(key, canonical_json(authorization), hashlib.sha256).hexdigest()
    return authorization


def validate_authorization(
    manifest: Mapping[str, Any],
    authorization: Mapping[str, Any],
    *,
    signing_secret: str,
    now: datetime | None = None,
) -> None:
    current = (now or _utc_now()).astimezone(timezone.utc)
    validate_manifest(manifest, now=current)
    if authorization.get("schema_version") != P2_AUTHORIZATION_SCHEMA:
        raise P2Error(f"authorization.schema_version: expected {P2_AUTHORIZATION_SCHEMA!r}")
    expected_fields = {
        "manifest_sha256": document_sha256(manifest),
        "experiment_id": manifest["experiment_id"],
        "target_id": manifest["target"]["id"],
        "operator_name": manifest["target"]["owner_name"],
        "expires_at_utc": manifest["authorization_expires_at_utc"],
        "signature_method": "typed-name+hmac-sha256/pbkdf2-v1",
        "attestation": P2_ATTESTATION,
    }
    for key, expected in expected_fields.items():
        if authorization.get(key) != expected:
            raise P2Error(f"authorization.{key}: does not match the manifest or required attestation")
    signed_at = _parse_timestamp(authorization.get("signed_at_utc"), "authorization.signed_at_utc")
    expires = _parse_timestamp(authorization.get("expires_at_utc"), "authorization.expires_at_utc")
    if signed_at > current + timedelta(minutes=5):
        raise P2Error("authorization.signed_at_utc: cannot be in the future")
    if signed_at >= expires or expires - signed_at > MAX_P2_AUTHORIZATION_AGE:
        raise P2Error("authorization validity window must be greater than zero and no more than 24 hours")
    if expires <= current:
        raise P2Error("authorization has expired")
    operator_name = str(authorization["operator_name"])
    if authorization.get("signature_text") != signing_challenge(manifest, operator_name):
        raise P2Error("authorization.signature_text: invalid signing challenge")
    kdf = _require(authorization, "signature_kdf", dict, "authorization")
    if kdf.get("name") != "pbkdf2-hmac-sha256" or kdf.get("iterations") != P2_SIGNATURE_KDF_ITERATIONS:
        raise P2Error("authorization.signature_kdf: unsupported parameters")
    salt_hex = kdf.get("salt_hex")
    if not isinstance(salt_hex, str):
        raise P2Error("authorization.signature_kdf.salt_hex: expected string")
    try:
        salt = bytes.fromhex(salt_hex)
    except ValueError as exc:
        raise P2Error("authorization.signature_kdf.salt_hex: invalid hexadecimal") from exc
    if len(salt) != 16:
        raise P2Error("authorization.signature_kdf.salt_hex: expected 16-byte salt")
    signature = authorization.get("signature_hmac_sha256")
    if not isinstance(signature, str) or not _SHA256_RE.fullmatch(signature):
        raise P2Error("authorization.signature_hmac_sha256: expected lowercase SHA-256")
    unsigned = dict(authorization)
    unsigned.pop("signature_hmac_sha256", None)
    key = hashlib.pbkdf2_hmac(
        "sha256",
        signing_secret.encode("utf-8"),
        salt,
        P2_SIGNATURE_KDF_ITERATIONS,
    )
    expected_signature = hmac.new(key, canonical_json(unsigned), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise P2Error("authorization signature is invalid or the signing passphrase is incorrect")


def manifest_template(*, experiment_id: str, expires_at_utc: str) -> dict[str, Any]:
    return {
        "schema_version": P2_MANIFEST_SCHEMA,
        "experiment_id": experiment_id,
        "title": "REPLACE WITH A PRECISE EXPERIMENT TITLE",
        "purpose": "research-and-study",
        "probe_level": 2,
        "authorization_expires_at_utc": expires_at_utc,
        "target": {
            "id": "REPLACE WITH A STABLE PHYSICAL TARGET ID",
            "description": "REPLACE WITH MAKE, MODEL, SERIAL, AND BUS LOCATION",
            "owner_name": "REPLACE WITH THE OPERATOR'S LEGAL NAME",
            "interface": "REPLACE WITH THE EXACT LOCAL INTERFACE",
            "remote": False,
            "shared": False,
            "production": False,
            "life_safety": False,
        },
        "operation": {
            "adapter": "REPLACE WITH A CODE-REVIEWED ADAPTER",
            "command": "REPLACE WITH AN ALLOWLISTED COMMAND NAME",
            "parameters": {},
            "request_sha256": "0" * 64,
            "timeout_seconds": 1.0,
            "response_limit_bytes": 4096,
            "max_attempts": 1,
        },
        "documented_side_effects": ["REPLACE; 'none known' is not a safety guarantee"],
        "maximum_credible_harm": ["REPLACE WITH THE WORST CREDIBLE OUTCOME"],
        "recovery_plan": ["REPLACE WITH A TESTED RECOVERY PROCEDURE"],
        "data_classes": ["hardware-metadata"],
        "rf_transmission_possible": False,
        "rf_authorization_reference": None,
    }


class _P2Trace:
    def __init__(self, root: Path, experiment_id: str):
        directory = root / "p2-runs"
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.path = directory / f"{experiment_id}.jsonl"
        try:
            self._descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise P2Error(f"experiment {experiment_id} has already been consumed in this evidence store") from exc
        self._sequence = 0

    def append(self, event: str, **fields: object) -> None:
        record = {
            "sequence": self._sequence,
            "recorded_at_utc": _timestamp(),
            "event": event,
            **fields,
        }
        payload = canonical_json(record) + b"\n"
        view = memoryview(payload)
        while view:
            written = os.write(self._descriptor, view)
            if written <= 0:
                raise OSError("could not append P2 trace")
            view = view[written:]
        os.fsync(self._descriptor)
        self._sequence += 1

    def close(self) -> None:
        if self._descriptor >= 0:
            os.close(self._descriptor)
            self._descriptor = -1


def execute_p2(
    manifest: Mapping[str, Any],
    authorization: Mapping[str, Any],
    *,
    adapter: P2Transport,
    evidence_dir: Path,
    signing_secret: str,
    before_exchange: Callable[[], None] | None = None,
) -> P2RunResult:
    """Run one authorized, allowlisted P2 exchange and consume its experiment ID."""
    validate_authorization(manifest, authorization, signing_secret=signing_secret)
    operation = manifest["operation"]
    if operation["adapter"] != adapter.name:
        raise P2Error("manifest adapter does not match the selected code-reviewed adapter")
    command = str(operation["command"])
    if command not in adapter.allowed_commands:
        raise P2Error(f"command {command!r} is not allowlisted by adapter {adapter.name!r}")
    request = adapter.serialize(command, operation["parameters"])
    request_digest = hashlib.sha256(request).hexdigest()
    if request_digest != operation["request_sha256"]:
        raise P2Error("serialized request does not match manifest.operation.request_sha256")

    evidence_store = ContentAddressedStore(evidence_dir)
    trace = _P2Trace(evidence_dir, str(manifest["experiment_id"]))
    try:
        evidence_store.put(request_digest, request)
        trace.append(
            "authorization_verified",
            manifest_sha256=document_sha256(manifest),
            authorization_signature_sha256=authorization["signature_hmac_sha256"],
            operator_name=authorization["operator_name"],
            target_id=manifest["target"]["id"],
        )
        trace.append(
            "request_committed_before_dispatch",
            adapter=adapter.name,
            command=command,
            request_sha256=request_digest,
            request_size=len(request),
        )
        if before_exchange is not None:
            before_exchange()
        response = adapter.exchange(
            manifest["target"],
            request,
            timeout_seconds=float(operation["timeout_seconds"]),
            response_limit_bytes=int(operation["response_limit_bytes"]),
        )
        if not isinstance(response, bytes):
            raise P2Error("adapter returned a non-bytes response")
        if len(response) > operation["response_limit_bytes"]:
            raise P2Error("adapter returned more bytes than the manifest permits")
        response_digest = hashlib.sha256(response).hexdigest()
        evidence_store.put(response_digest, response)
        trace.append(
            "response_received",
            response_sha256=response_digest,
            response_size=len(response),
        )
        return P2RunResult(
            experiment_id=str(manifest["experiment_id"]),
            request_sha256=request_digest,
            response_sha256=response_digest,
            response_size=len(response),
            trace_path=trace.path,
        )
    except BaseException as exc:
        trace.append("experiment_stopped", error_type=type(exc).__name__)
        raise
    finally:
        trace.close()
