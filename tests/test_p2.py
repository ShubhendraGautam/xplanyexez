from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from hwprobe.cli import main
from hwprobe.p2 import (
    P2Error,
    create_authorization,
    execute_p2,
    signing_challenge,
    validate_authorization,
    validate_manifest,
)


SIGNING_SECRET = "correct horse battery staple"


class FakeIdentifyAdapter:
    name = "test-identify"
    allowed_commands = frozenset({"identify"})
    request = b"\x49\x44\x00\x01"

    def serialize(self, command, parameters):
        if command != "identify" or parameters != {"page": 1}:
            raise AssertionError("unexpected command")
        return self.request

    def exchange(self, target, request, *, timeout_seconds, response_limit_bytes):
        if target["id"] != "fixture-001" or request != self.request:
            raise AssertionError("unexpected exchange")
        return b"fixture-response"


def valid_manifest(*, expires: datetime | None = None) -> dict[str, object]:
    adapter = FakeIdentifyAdapter()
    return {
        "schema_version": "xplanyexez-p2-manifest/v1",
        "experiment_id": str(uuid4()),
        "title": "Read fixture identity page",
        "purpose": "research-and-study",
        "probe_level": 2,
        "authorization_expires_at_utc": (expires or datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "target": {
            "id": "fixture-001",
            "description": "owned isolated protocol fixture",
            "owner_name": "Test Operator",
            "interface": "fixture://local/001",
            "remote": False,
            "shared": False,
            "production": False,
            "life_safety": False,
        },
        "operation": {
            "adapter": adapter.name,
            "command": "identify",
            "parameters": {"page": 1},
            "request_sha256": hashlib.sha256(adapter.request).hexdigest(),
            "timeout_seconds": 1.0,
            "response_limit_bytes": 1024,
            "max_attempts": 1,
        },
        "documented_side_effects": ["none documented; device may wake"],
        "maximum_credible_harm": ["fixture may require a power cycle"],
        "recovery_plan": ["disconnect and power-cycle the owned fixture"],
        "data_classes": ["hardware-metadata"],
        "rf_transmission_possible": False,
        "rf_authorization_reference": None,
    }


def signed(manifest: dict[str, object]) -> dict[str, object]:
    name = str(manifest["target"]["owner_name"])
    return create_authorization(
        manifest,
        operator_name=name,
        signature_text=signing_challenge(manifest, name),
        signing_secret=SIGNING_SECRET,
    )


class P2AuthorizationTests(unittest.TestCase):
    def test_valid_authorization_is_bound_to_manifest(self) -> None:
        manifest = valid_manifest()
        authorization = signed(manifest)
        validate_authorization(manifest, authorization, signing_secret=SIGNING_SECRET)
        manifest["operation"]["timeout_seconds"] = 2.0
        with self.assertRaisesRegex(P2Error, "manifest_sha256"):
            validate_authorization(manifest, authorization, signing_secret=SIGNING_SECRET)

    def test_operator_must_be_the_declared_owner(self) -> None:
        manifest = valid_manifest()
        with self.assertRaisesRegex(P2Error, "owner_name"):
            create_authorization(
                manifest,
                operator_name="Different Person",
                signature_text=signing_challenge(manifest, "Different Person"),
                signing_secret=SIGNING_SECRET,
            )

    def test_expired_or_shared_manifest_is_rejected(self) -> None:
        expired = valid_manifest(expires=datetime.now(timezone.utc) - timedelta(seconds=1))
        with self.assertRaisesRegex(P2Error, "expired"):
            validate_manifest(expired)
        shared = valid_manifest()
        shared["target"]["shared"] = True
        with self.assertRaisesRegex(P2Error, "shared targets"):
            validate_manifest(shared)

    def test_rf_requires_authorization_reference(self) -> None:
        manifest = valid_manifest()
        manifest["rf_transmission_possible"] = True
        with self.assertRaisesRegex(P2Error, "rf_authorization_reference"):
            validate_manifest(manifest)

    def test_template_placeholders_and_zero_digest_are_rejected(self) -> None:
        manifest = valid_manifest()
        manifest["title"] = "REPLACE WITH TITLE"
        with self.assertRaisesRegex(P2Error, "placeholder"):
            validate_manifest(manifest)
        manifest = valid_manifest()
        manifest["operation"]["request_sha256"] = "0" * 64
        with self.assertRaisesRegex(P2Error, "template digest"):
            validate_manifest(manifest)

    def test_signature_requires_the_operator_passphrase(self) -> None:
        manifest = valid_manifest()
        authorization = signed(manifest)
        with self.assertRaisesRegex(P2Error, "signature is invalid"):
            validate_authorization(manifest, authorization, signing_secret="incorrect passphrase")

    def test_initial_p2_policy_rejects_sensitive_data_classes(self) -> None:
        manifest = valid_manifest()
        manifest["data_classes"] = ["hardware-metadata", "credentials"]
        with self.assertRaisesRegex(P2Error, "credentials"):
            validate_manifest(manifest)


class P2ExecutionTests(unittest.TestCase):
    def test_request_is_sealed_and_traced_before_exchange(self) -> None:
        manifest = valid_manifest()
        authorization = signed(manifest)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            trace = evidence / "p2-runs" / f"{manifest['experiment_id']}.jsonl"

            def assert_precommitted() -> None:
                events = [json.loads(line)["event"] for line in trace.read_text(encoding="utf-8").splitlines()]
                self.assertEqual(events, ["authorization_verified", "request_committed_before_dispatch"])

            result = execute_p2(
                manifest,
                authorization,
                adapter=FakeIdentifyAdapter(),
                evidence_dir=evidence,
                signing_secret=SIGNING_SECRET,
                before_exchange=assert_precommitted,
            )
            events = [json.loads(line)["event"] for line in trace.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(events[-1], "response_received")
            self.assertEqual(result.response_size, len(b"fixture-response"))
            self.assertTrue(
                (evidence / "objects" / "sha256" / result.request_sha256[:2] / result.request_sha256).is_file()
            )

    def test_experiment_id_is_single_use_per_evidence_store(self) -> None:
        manifest = valid_manifest()
        authorization = signed(manifest)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            execute_p2(
                manifest,
                authorization,
                adapter=FakeIdentifyAdapter(),
                evidence_dir=evidence,
                signing_secret=SIGNING_SECRET,
            )
            with self.assertRaisesRegex(P2Error, "already been consumed"):
                execute_p2(
                    manifest,
                    authorization,
                    adapter=FakeIdentifyAdapter(),
                    evidence_dir=evidence,
                    signing_secret=SIGNING_SECRET,
                )

    def test_unallowlisted_command_is_rejected_before_trace_creation(self) -> None:
        manifest = valid_manifest()
        manifest["operation"]["command"] = "reset"
        authorization = signed(manifest)
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory)
            with self.assertRaisesRegex(P2Error, "not allowlisted"):
                execute_p2(
                    manifest,
                    authorization,
                    adapter=FakeIdentifyAdapter(),
                    evidence_dir=evidence,
                    signing_secret=SIGNING_SECRET,
                )
            self.assertFalse((evidence / "p2-runs").exists())


class P2CliTests(unittest.TestCase):
    def test_disclaimer_is_available_from_cli(self) -> None:
        with patch("builtins.print") as output:
            self.assertEqual(main(["p2", "disclaimer"]), 0)
        self.assertIn("OWNERSHIP AND RESEARCH ATTESTATION", output.call_args.args[0])

    def test_interactive_authorization_and_verification(self) -> None:
        manifest = valid_manifest()
        challenge = signing_challenge(manifest, "Test Operator")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            authorization_path = root / "authorization.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            with (
                patch("hwprobe.cli.sys.stdin.isatty", return_value=True),
                patch("builtins.input", side_effect=["Test Operator", challenge]),
                patch("hwprobe.cli.getpass.getpass", side_effect=[SIGNING_SECRET, SIGNING_SECRET]),
                patch("builtins.print"),
            ):
                self.assertEqual(
                    main(["p2", "authorize", str(manifest_path), "--output", str(authorization_path)]),
                    0,
                )
            self.assertEqual(authorization_path.stat().st_mode & 0o777, 0o600)
            with (
                patch("hwprobe.cli.sys.stdin.isatty", return_value=True),
                patch("hwprobe.cli.getpass.getpass", return_value=SIGNING_SECRET),
                patch("builtins.print"),
            ):
                self.assertEqual(main(["p2", "verify", str(manifest_path), str(authorization_path)]), 0)

    def test_run_refuses_unregistered_adapter(self) -> None:
        manifest = valid_manifest()
        authorization = signed(manifest)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest_path = root / "manifest.json"
            authorization_path = root / "authorization.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            authorization_path.write_text(json.dumps(authorization), encoding="utf-8")
            with (
                patch("hwprobe.cli.sys.stdin.isatty", return_value=True),
                patch("hwprobe.cli.getpass.getpass", return_value=SIGNING_SECRET),
                patch("builtins.print"),
            ):
                self.assertEqual(
                    main([
                        "p2",
                        "run",
                        str(manifest_path),
                        str(authorization_path),
                        "--evidence-dir",
                        str(root / "evidence"),
                    ]),
                    2,
                )
            self.assertFalse((root / "evidence").exists())


if __name__ == "__main__":
    unittest.main()
