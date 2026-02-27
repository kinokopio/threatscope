#!/usr/bin/env python3
"""Diagnose static analysis performance issues."""

import asyncio
import time
import sys
from pathlib import Path


def test_step(name, func):
    """Test a single step and report timing."""
    print(f"  {name}...", end=" ", flush=True)
    start = time.time()
    try:
        result = func()
        elapsed = time.time() - start
        print(f"OK ({elapsed:.3f}s)")
        return True, elapsed
    except Exception as e:
        elapsed = time.time() - start
        print(f"FAILED ({elapsed:.3f}s): {e}")
        return False, elapsed


async def test_step_async(name, coro):
    """Test an async step and report timing."""
    print(f"  {name}...", end=" ", flush=True)
    start = time.time()
    try:
        result = await coro
        elapsed = time.time() - start
        print(f"OK ({elapsed:.3f}s)")
        return True, elapsed, result
    except Exception as e:
        elapsed = time.time() - start
        print(f"FAILED ({elapsed:.3f}s): {e}")
        return False, elapsed, None


async def main():
    print("=" * 50)
    print("ThreatScope Static Analysis Diagnostic")
    print("=" * 50)
    print()

    # Find test file
    test_file = None
    for path in [Path("/tmp/threatscope"), Path("/var/tmp/threatscope")]:
        if path.exists():
            files = list(path.glob("*"))
            if files:
                test_file = files[0]
                break

    if not test_file:
        print("No test file found. Please upload a file first.")
        print("Or specify a file path as argument.")
        if len(sys.argv) > 1:
            test_file = Path(sys.argv[1])
        else:
            return

    print(f"Test file: {test_file}")
    print(f"File size: {test_file.stat().st_size / 1024 / 1024:.2f} MB")
    print()

    # Test each component
    print("Testing individual components:")
    print()

    # 1. Hash Calculator
    print("1. Hash Calculator")
    from tools.static.hash_calculator import HashCalculator

    calc = HashCalculator()
    ok, elapsed, _ = await test_step_async("  analyze", calc.analyze(test_file))
    print()

    # 2. String Extractor
    print("2. String Extractor")
    from tools.static.string_extractor import StringExtractor

    extractor = StringExtractor()
    ok, elapsed, result = await test_step_async("  analyze", extractor.analyze(test_file))
    if result and result.success:
        print(f"     Total strings: {result.data.get('total_strings', 0)}")
    print()

    # 3. ELF Parser
    print("3. ELF Parser")
    from tools.static.elf_parser import ELFParser

    parser = ELFParser()
    ok, elapsed, result = await test_step_async("  analyze", parser.analyze(test_file))
    if result and result.success:
        print(f"     Format: {result.data.get('format', 'N/A')}")
        print(f"     Arch: {result.data.get('arch', 'N/A')}")
    print()

    # 4. YARA Scanner
    print("4. YARA Scanner")
    from tools.static.yara_scanner import YaraScanner

    scanner = YaraScanner("rules/yara")

    print("  Loading rules...", end=" ", flush=True)
    start = time.time()
    scanner.load_rules("rules/yara")
    print(f"OK ({time.time() - start:.3f}s)")

    ok, elapsed, result = await test_step_async("  analyze", scanner.analyze(test_file))
    if result and result.success:
        matches = result.data.get("matches", [])
        print(f"     Matches: {len(matches)}")
        for m in matches[:3]:
            print(f"       - {m['rule']}")
    print()

    # 5. Full Static Analyzer
    print("5. Full Static Analyzer")
    from tools.static.analyzer import StaticAnalyzer

    analyzer = StaticAnalyzer(yara_rules_path="rules/yara")
    ok, elapsed, result = await test_step_async("  analyze", analyzer.analyze(test_file))
    if result:
        print(f"     Keys: {list(result.keys())}")
    print()

    print("=" * 50)
    print("Diagnostic complete!")


if __name__ == "__main__":
    asyncio.run(main())
