from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from hwprobe.fpga import BOARD_PROFILES, discover_usb_debuggers, get_board_profile
from hwprobe.handlers import HANDLERS
from hwprobe.p2 import (
    P2_ATTESTATION,
    P2_DISCLAIMER,
    P2Error,
    create_authorization,
    document_sha256,
    execute_p2,
    load_json_object,
    manifest_template,
    signing_challenge,
    validate_authorization,
    validate_manifest,
)
from hwprobe.p2_adapters import ADAPTERS, adapter_descriptors, get_adapter
from hwprobe.policy import RedactionMode, ScanPolicy
from hwprobe.provenance import ContentAddressedStore, EvidenceError, verify_evidence
from hwprobe.qualification import qualify_inventory
from hwprobe.scanner import scan
from hwprobe.schema import SchemaError, validate_inventory


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="hwprobe", description="Evidence-backed hardware discovery")
    subcommands = root.add_subparsers(dest="command", required=True)
    scan_parser = subcommands.add_parser("scan", help="scan hardware and emit JSON")
    scan_parser.add_argument("--pretty", action="store_true", help="indent JSON output")
    scan_parser.add_argument("--output", type=Path, help="write JSON to this file instead of stdout")
    scan_parser.add_argument("--handler", action="append", default=[], help="include only this handler (repeatable)")
    scan_parser.add_argument("--exclude-handler", action="append", default=[], help="exclude this handler (repeatable)")
    scan_parser.add_argument("--timeout", type=float, default=10.0, help="maximum seconds per handler")
    scan_parser.add_argument("--scan-timeout", type=float, default=120.0, help="maximum seconds for the entire scan")
    scan_parser.add_argument(
        "--evidence-dir",
        type=Path,
        help="store private raw evidence by content digest (contains sensitive data)",
    )
    scan_parser.add_argument(
        "--redaction",
        choices=[mode.value for mode in RedactionMode],
        default=RedactionMode.IDENTIFIERS.value,
        help="output redaction profile (default: identifiers)",
    )
    subcommands.add_parser("handlers", help="list registered category handlers")
    validate_parser = subcommands.add_parser("validate", help="validate an inventory JSON document")
    validate_parser.add_argument("inventory", type=Path)
    verify_parser = subcommands.add_parser("verify-evidence", help="verify every evidence object referenced by an inventory")
    verify_parser.add_argument("inventory", type=Path)
    verify_parser.add_argument("--evidence-dir", type=Path, required=True)
    qualify_parser = subcommands.add_parser("qualify", help="evaluate an inventory for platform validation")
    qualify_parser.add_argument("inventory", type=Path)
    qualify_parser.add_argument("--evidence-dir", type=Path)
    fpga_parser = subcommands.add_parser("fpga", help="inspect supported FPGA board/debugger infrastructure")
    fpga_commands = fpga_parser.add_subparsers(dest="fpga_command", required=True)
    fpga_commands.add_parser("boards", help="list reviewed FPGA board profiles")
    fpga_discover = fpga_commands.add_parser("discover", help="inventory USB descriptors without endpoint traffic")
    fpga_discover.add_argument("--board", default="tang-primer-25k-dock", choices=sorted(BOARD_PROFILES))
    fpga_discover.add_argument("--pretty", action="store_true", help="indent JSON output")
    fpga_discover.add_argument(
        "--include-identifiers",
        action="store_true",
        help="include USB serial values in this private output",
    )
    p2_parser = subcommands.add_parser("p2", help="authorize and run controlled Level 2 experiments")
    p2_commands = p2_parser.add_subparsers(dest="p2_command", required=True)
    p2_commands.add_parser("disclaimer", help="display the mandatory P2 disclaimer")
    p2_commands.add_parser("adapters", help="list executable and blocked P2 adapters")
    p2_init = p2_commands.add_parser("init", help="write a fail-closed P2 manifest template")
    p2_init.add_argument("--output", type=Path, required=True)
    p2_authorize = p2_commands.add_parser("authorize", help="interactively sign one P2 manifest")
    p2_authorize.add_argument("manifest", type=Path)
    p2_authorize.add_argument("--output", type=Path, required=True)
    p2_verify = p2_commands.add_parser("verify", help="verify a P2 manifest and authorization")
    p2_verify.add_argument("manifest", type=Path)
    p2_verify.add_argument("authorization", type=Path)
    p2_run = p2_commands.add_parser("run", help="run one authorized experiment with a reviewed adapter")
    p2_run.add_argument("manifest", type=Path)
    p2_run.add_argument("authorization", type=Path)
    p2_run.add_argument("--evidence-dir", type=Path, required=True)
    return root


def _write_new_private_json(path: Path, document: dict[str, object]) -> None:
    path = path.resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = json.dumps(document, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise P2Error(f"refusing to overwrite existing file: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _p2_main(args: argparse.Namespace) -> int:
    if args.p2_command == "disclaimer":
        print(P2_DISCLAIMER)
        return 0
    if args.p2_command == "adapters":
        for descriptor in adapter_descriptors():
            executable = descriptor.name in ADAPTERS
            state = "executable" if executable else descriptor.status
            commands = ",".join(descriptor.planned_commands)
            print(f"{descriptor.name}\t{state}\tcommands={commands}\t{descriptor.reason}")
        return 0
    if args.p2_command == "init":
        expires = datetime.now(timezone.utc) + timedelta(hours=24)
        template = manifest_template(experiment_id=str(uuid4()), expires_at_utc=expires.isoformat())
        try:
            _write_new_private_json(args.output, template)
        except P2Error as exc:
            print(f"P2 configuration error: {exc}", file=sys.stderr)
            return 2
        print(f"wrote P2 manifest template: {args.output}")
        print("Replace every REPLACE value, register a code-reviewed adapter, then authorize it.")
        return 0

    try:
        manifest = load_json_object(args.manifest, kind="P2 manifest")
        validate_manifest(manifest)
        if args.p2_command == "authorize":
            print(P2_DISCLAIMER)
            print(f"Manifest SHA-256: {document_sha256(manifest)}")
            print(f"Experiment: {manifest['experiment_id']} — {manifest['title']}")
            print(f"Target: {manifest['target']['id']} — {manifest['target']['description']}")
            print(f"Declared owner: {manifest['target']['owner_name']}")
            print(f"Command: {manifest['operation']['adapter']} / {manifest['operation']['command']}")
            print(f"\nAttestation:\n{P2_ATTESTATION}\n")
            if not sys.stdin.isatty():
                raise P2Error("interactive terminal required for operator signing")
            operator_name = input("Operator legal name: ").strip()
            challenge = signing_challenge(manifest, operator_name)
            print(f"Type this signing challenge exactly:\n{challenge}")
            signature = input("Signature: ")
            signing_secret = getpass.getpass("Signing passphrase (12+ characters): ")
            signing_secret_confirmation = getpass.getpass("Repeat signing passphrase: ")
            if signing_secret != signing_secret_confirmation:
                raise P2Error("signing passphrases did not match")
            authorization = create_authorization(
                manifest,
                operator_name=operator_name,
                signature_text=signature,
                signing_secret=signing_secret,
            )
            _write_new_private_json(args.output, authorization)
            print(f"wrote sealed self-attestation: {args.output}")
            return 0

        authorization = load_json_object(args.authorization, kind="P2 authorization")
        if not sys.stdin.isatty():
            raise P2Error("interactive terminal required to unlock the operator signature")
        signing_secret = getpass.getpass("Signing passphrase: ")
        validate_authorization(manifest, authorization, signing_secret=signing_secret)
        if args.p2_command == "verify":
            print("P2 manifest and self-attestation are valid and unexpired")
            print("Self-attestation does not independently verify identity, ownership, qualification, or legality.")
            return 0
        print(P2_DISCLAIMER)
        adapter = get_adapter(str(manifest["operation"]["adapter"]))
        result = execute_p2(
            manifest,
            authorization,
            adapter=adapter,
            evidence_dir=args.evidence_dir,
            signing_secret=signing_secret,
        )
        print(json.dumps({
            "experiment_id": result.experiment_id,
            "request_sha256": result.request_sha256,
            "response_sha256": result.response_sha256,
            "response_size": result.response_size,
            "trace_path": str(result.trace_path),
        }, indent=2, sort_keys=True))
        return 0
    except (P2Error, ValueError) as exc:
        print(f"P2 authorization error: {exc}", file=sys.stderr)
        return 2


def select_handlers(included: list[str], excluded: list[str]) -> tuple[type, ...]:
    by_name = {handler_type.name: handler_type for handler_type in HANDLERS}
    unknown = sorted((set(included) | set(excluded)) - by_name.keys())
    if unknown:
        raise ValueError(f"unknown handler(s): {', '.join(unknown)}")
    selected_names = tuple(dict.fromkeys(included)) if included else tuple(by_name)
    selected = tuple(by_name[name] for name in selected_names)
    excluded_set = set(excluded)
    return tuple(handler_type for handler_type in selected if handler_type.name not in excluded_set)


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.command == "p2":
        return _p2_main(args)
    if args.command == "fpga":
        if args.fpga_command == "boards":
            for name in sorted(BOARD_PROFILES):
                profile = get_board_profile(name)
                print(
                    f"{profile.name}\t{profile.fpga_family}\t"
                    f"idcode={','.join(profile.expected_idcodes)}\t{profile.display_name}"
                )
            return 0
        report = discover_usb_debuggers(
            args.board,
            include_identifiers=args.include_identifiers,
        )
        print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
        return 0
    if args.command == "handlers":
        for handler_type in HANDLERS:
            capabilities = handler_type.capabilities()
            levels = ",".join(str(level) for level in capabilities["supported_probe_levels"])
            print(f"{handler_type.name}\t{handler_type.category}\tlevels={levels}\ttimeout={capabilities['default_timeout_seconds']}s")
        return 0
    if args.command in {"validate", "verify-evidence", "qualify"}:
        try:
            document = json.loads(args.inventory.read_text(encoding="utf-8"))
            validate_inventory(document)
            if args.command == "verify-evidence":
                result = verify_evidence(document, ContentAddressedStore(args.evidence_dir))
            elif args.command == "qualify":
                qualification = qualify_inventory(document, evidence_dir=args.evidence_dir)
        except (OSError, json.JSONDecodeError, SchemaError, EvidenceError) as exc:
            print(f"invalid inventory: {exc}", file=sys.stderr)
            return 1
        if args.command == "verify-evidence":
            print(f"verified {result['objects_verified']} objects ({result['bytes_verified']} bytes)")
            return 0
        if args.command == "qualify":
            print(json.dumps(qualification, indent=2, sort_keys=True))
            return 0 if qualification["qualified"] else 1
        print("valid inventory")
        return 0
    try:
        handlers = select_handlers(args.handler, args.exclude_handler)
        policy = ScanPolicy(
            handler_timeout_seconds=args.timeout,
            scan_timeout_seconds=args.scan_timeout,
            redaction=RedactionMode(args.redaction),
        )
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    evidence_store = ContentAddressedStore(args.evidence_dir) if args.evidence_dir else None
    try:
        document = scan(handlers, policy=policy, evidence_store=evidence_store)
    except (OSError, EvidenceError) as exc:
        print(f"collection error: {exc}", file=sys.stderr)
        return 1
    rendered = json.dumps(document, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0
