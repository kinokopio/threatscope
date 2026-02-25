#!/usr/bin/env python3
"""ThreatScope CLI - AI-driven malware analysis."""

import argparse
import asyncio
import json
import sys
from pathlib import Path


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ThreatScope - AI-driven malware analysis framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "file",
        type=Path,
        help="File to analyze",
    )
    parser.add_argument(
        "--no-ghidra",
        action="store_true",
        help="Disable Ghidra deep analysis",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        help="Output file for JSON report",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress progress output",
    )

    args = parser.parse_args()

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Run analysis
    result = asyncio.run(run_analysis(args))

    # Output result
    output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        args.output.write_text(output)
        if not args.quiet:
            print(f"Report saved to: {args.output}")
    else:
        print(output)


async def run_analysis(args) -> dict:
    """Run the analysis pipeline."""
    from core import AnalysisCoordinator

    if not args.quiet:
        print(f"Analyzing: {args.file}")

    coordinator = AnalysisCoordinator()
    result = await coordinator.analyze(
        file_path=args.file,
        enable_ghidra=not args.no_ghidra,
    )

    return result


if __name__ == "__main__":
    main()
