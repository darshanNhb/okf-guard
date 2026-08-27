"""Command-Line Interface for okf-guard.

Provides subcommands for scanning files/directories and reviewing
quarantined results.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from okfguard.api import get_adapter_for_extension, sanitize
from okfguard.core.models import Config


def _print_scan_summary(path: str, result: Any) -> None:
    """Print a human-readable summary of a scan result."""
    action = result.action
    score = result.risk_score
    flags = result.flags

    print(f"\n--- {path} ---")
    print(f"Action:     {action.upper()}")
    print(f"Risk Score: {score:.3f}")
    
    if flags:
        print(f"Flags ({len(flags)}):")
        for f in flags:
            print(f"  - [{f.type}] {f.location}")
            print(f"    Confidence: {f.confidence:.2f}")
            print(f"    Snippet:    {f.snippet!r}")
    else:
        print("Flags:      None")


def _run_scan(args: argparse.Namespace) -> int:
    """Handle the 'scan' subcommand."""
    config = Config()
    target_path = args.path
    is_json = args.json
    is_recursive = args.recursive

    if not os.path.exists(target_path):
        print(f"Error: Path not found: {target_path}", file=sys.stderr)
        return 3  # Hard failure for invalid path

    paths_to_scan: list[str] = []
    if os.path.isfile(target_path):
        paths_to_scan.append(target_path)
    elif os.path.isdir(target_path):
        if not is_recursive:
            print(
                f"Error: {target_path} is a directory. "
                "Use --recursive to scan directories.",
                file=sys.stderr
            )
            return 3
        for root, _, files in os.walk(target_path):
            for f in files:
                ext = os.path.splitext(f)[1]
                if get_adapter_for_extension(ext) is not None:
                    paths_to_scan.append(os.path.join(root, f))
    else:
        print(f"Error: {target_path} is neither file nor directory.", file=sys.stderr)
        return 3

    if not paths_to_scan:
        print(f"No supported files found to scan in {target_path}.", file=sys.stderr)
        return 0

    stats = {"pass": 0, "quarantine": 0, "block": 0, "error": 0}
    max_exit_code = 0

    for path in paths_to_scan:
        try:
            result = sanitize(path, config=config)
            stats[result.action] += 1
            
            if result.action == "block":
                max_exit_code = max(max_exit_code, 2)
            elif result.action == "quarantine":
                max_exit_code = max(max_exit_code, 1)

            if is_json:
                # Output newline-delimited JSON per spec
                out_obj = {
                    "path": path,
                    "action": result.action,
                    "risk_score": result.risk_score,
                    "flags": [
                        {
                            "type": f.type,
                            "location": f.location,
                            "snippet": f.snippet,
                            "confidence": f.confidence,
                        }
                        for f in result.flags
                    ],
                }
                print(json.dumps(out_obj))
            else:
                _print_scan_summary(path, result)

        except Exception as exc:
            stats["error"] += 1
            max_exit_code = max(max_exit_code, 3)
            if is_json:
                print(json.dumps({"path": path, "error": str(exc)}))
            else:
                print(f"\n--- {path} ---")
                print(f"Error scanning file: {exc}")

    if not is_json and len(paths_to_scan) > 1:
        print("\n=== Scan Summary ===")
        print(f"Total files: {len(paths_to_scan)}")
        print(f"Pass:        {stats['pass']}")
        print(f"Quarantine:  {stats['quarantine']}")
        print(f"Block:       {stats['block']}")
        if stats["error"]:
            print(f"Errors:      {stats['error']}")

    return max_exit_code


def _run_review(args: argparse.Namespace) -> int:
    """Handle the 'review' subcommand."""
    log_path = args.json_log
    
    if not os.path.isfile(log_path):
        print(f"Error: Log file not found: {log_path}", file=sys.stderr)
        return 3

    items = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                items.append(obj)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON on line {line_num} of {log_path}", file=sys.stderr)
                return 3

    quarantined = [item for item in items if item.get("action") == "quarantine"]

    if not quarantined:
        print("No quarantined items found in the log to review.")
        return 0

    print(f"Found {len(quarantined)} quarantined item(s) to review.\n")
    
    stats = {"approved": 0, "rejected": 0, "skipped": 0}

    for idx, item in enumerate(quarantined, start=1):
        path = item.get("path", "unknown")
        score = item.get("risk_score", 0.0)
        flags = item.get("flags", [])

        print(f"--- Item {idx} of {len(quarantined)} ---")
        print(f"File:       {path}")
        print(f"Risk Score: {score}")
        print(f"Flags ({len(flags)}):")
        for f in flags:
            print(f"  - [{f.get('type')}] {f.get('location')}")
            print(f"    Confidence: {f.get('confidence')}")
            print(f"    Snippet:    {f.get('snippet')!r}")
        print()

        while True:
            choice = input("Decision [a]pprove / [r]eject / [s]kip: ").strip().lower()
            if choice in ("a", "approve"):
                stats["approved"] += 1
                break
            elif choice in ("r", "reject"):
                stats["rejected"] += 1
                break
            elif choice in ("s", "skip"):
                stats["skipped"] += 1
                break
            else:
                print("Invalid choice. Please enter 'a', 'r', or 's'.")

        print()

    print("=== Review Summary ===")
    print(f"Approved: {stats['approved']}")
    print(f"Rejected: {stats['rejected']}")
    print(f"Skipped:  {stats['skipped']}")

    return 0


def main() -> int:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="okf-guard: Content-safety scanning for OKF generation pipelines."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- Scan subcommand ---
    scan_parser = subparsers.add_parser(
        "scan",
        description=(
            "Scan documents for hidden content and prompt-injection patterns.\n\n"
            "Exit Codes:\n"
            "  0: Pass (highest risk score is below quarantine threshold)\n"
            "  1: Quarantine (highest risk score reached quarantine threshold)\n"
            "  2: Block (highest risk score reached block threshold)\n"
            "  3: Error (file not found, missing dependency, or parsing crash)"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    scan_parser.add_argument(
        "path",
        help="Path to a file or directory to scan."
    )
    scan_parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        help="Recursively scan all supported files if path is a directory."
    )
    scan_parser.add_argument(
        "--json",
        action="store_true",
        help="Output machine-readable newline-delimited JSON instead of text summary."
    )

    # --- Review subcommand ---
    review_parser = subparsers.add_parser(
        "review",
        help=(
            "Interactively review quarantined scan results. "
            "Note: This is a triage aid only and does not modify OKF bundles."
        )
    )
    review_parser.add_argument(
        "--json-log",
        required=True,
        help="Path to a JSON log file produced by a prior 'scan --json' run."
    )

    args = parser.parse_args()

    if args.command == "scan":
        return _run_scan(args)
    elif args.command == "review":
        return _run_review(args)
    
    return 2


if __name__ == "__main__":
    sys.exit(main())
