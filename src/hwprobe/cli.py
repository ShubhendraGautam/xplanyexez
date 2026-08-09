from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from hwprobe.handlers import HANDLERS
from hwprobe.policy import RedactionMode, ScanPolicy
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
    scan_parser.add_argument(
        "--redaction",
        choices=[mode.value for mode in RedactionMode],
        default=RedactionMode.IDENTIFIERS.value,
        help="output redaction profile (default: identifiers)",
    )
    subcommands.add_parser("handlers", help="list registered category handlers")
    validate_parser = subcommands.add_parser("validate", help="validate an inventory JSON document")
    validate_parser.add_argument("inventory", type=Path)
    return root


def select_handlers(included: list[str], excluded: list[str]) -> tuple[type, ...]:
    by_name = {handler_type.name: handler_type for handler_type in HANDLERS}
    unknown = sorted((set(included) | set(excluded)) - by_name.keys())
    if unknown:
        raise ValueError(f"unknown handler(s): {', '.join(unknown)}")
    selected = tuple(by_name[name] for name in included) if included else HANDLERS
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
    if args.command == "validate":
        try:
            document = json.loads(args.inventory.read_text(encoding="utf-8"))
            validate_inventory(document)
        except (OSError, json.JSONDecodeError, SchemaError) as exc:
            print(f"invalid inventory: {exc}", file=sys.stderr)
            return 1
        print("valid inventory")
        return 0
    try:
        handlers = select_handlers(args.handler, args.exclude_handler)
        policy = ScanPolicy(
            handler_timeout_seconds=args.timeout,
            redaction=RedactionMode(args.redaction),
        )
    except ValueError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    document = scan(handlers, policy=policy)
    rendered = json.dumps(document, indent=2 if args.pretty else None, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0
