from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hwprobe.handlers import HANDLERS
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
    return root


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
