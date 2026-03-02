"""CLI for DSSP result scanning."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .regex_scanner import RegexScanner
from .ner_scanner import NERScanner
from .statistical_scanner import StatisticalScanner
from .llm_filter_scanner import LLMOutputFilterScanner


SCANNER_CLASSES = {
    "regex": RegexScanner,
    "ner": NERScanner,
    "statistical": StatisticalScanner,
    "llm_output_filter": LLMOutputFilterScanner,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="DSSP Reference Result Scanner")
    parser.add_argument("result", type=Path, help="Path to DSSP result envelope JSON")
    parser.add_argument(
        "--contract", type=Path, help="Path to DSP contract JSON (optional)"
    )
    parser.add_argument(
        "--scanners",
        nargs="+",
        choices=list(SCANNER_CLASSES.keys()),
        default=["regex"],
        help="Scanners to run (default: regex)",
    )
    parser.add_argument(
        "--output", type=Path, help="Output file for scan verdicts (default: stdout)"
    )
    parser.add_argument(
        "--quiet", action="store_true", help="Only output JSON, no status messages"
    )

    args = parser.parse_args()

    # Load result
    with open(args.result) as f:
        result = json.load(f)

    # Load contract if provided
    contract = None
    if args.contract:
        with open(args.contract) as f:
            contract = json.load(f)

    # Run scanners
    verdicts = []
    overall_passed = True

    for scanner_name in args.scanners:
        scanner = SCANNER_CLASSES[scanner_name]()
        if not args.quiet:
            print(f"Running {scanner_name} scanner...", file=sys.stderr)

        verdict = scanner.scan(result, contract)
        verdicts.append(verdict.to_dict())

        if not verdict.passed:
            overall_passed = False
            if not args.quiet:
                print(f"  FAILED: {len(verdict.findings)} finding(s)", file=sys.stderr)
        elif not args.quiet:
            print("  PASSED", file=sys.stderr)

    # Build output
    output = {
        "performed": True,
        "verdicts": verdicts,
        "overall_passed": overall_passed,
    }

    output_json = json.dumps(output, indent=2)

    if args.output:
        args.output.write_text(output_json)
        if not args.quiet:
            print(f"\nVerdicts written to {args.output}", file=sys.stderr)
    else:
        print(output_json)

    sys.exit(0 if overall_passed else 1)


if __name__ == "__main__":
    main()
