#!/usr/bin/env python3
"""Compile YARA rules into a single precompiled file for fast loading.

Usage:
    python compile_yara_rules.py [source_dir] [output_file]

Example:
    python compile_yara_rules.py rules/yara_full rules/yara/compiled_rules.yarc
"""

import sys
import time
from pathlib import Path

try:
    import yara
except ImportError:
    print("Error: yara-python not installed")
    print("Install with: pip install yara-python")
    sys.exit(1)


def compile_rules(source_dir: Path, output_file: Path) -> bool:
    """Compile all YARA rules in a directory to a single file."""

    print(f"Source directory: {source_dir}")
    print(f"Output file: {output_file}")
    print()

    # Find all rule files
    rule_files = list(source_dir.glob("*.yar")) + list(source_dir.glob("*.yara"))
    print(f"Found {len(rule_files)} rule files")

    # Validate and collect rules
    valid_files = {}
    errors = []

    print("Validating rules...")
    for i, rule_file in enumerate(sorted(rule_files)):
        try:
            # Test compile individually
            yara.compile(filepath=str(rule_file))
            # Use filename as namespace
            namespace = rule_file.stem.replace("-", "_").replace(".", "_")
            valid_files[namespace] = str(rule_file)
        except yara.SyntaxError as e:
            errors.append((rule_file.name, str(e)[:80]))
        except Exception as e:
            errors.append((rule_file.name, str(e)[:80]))

        # Progress indicator
        if (i + 1) % 200 == 0:
            print(f"  Validated {i + 1}/{len(rule_files)} files...")

    print(f"\nValid: {len(valid_files)} files")
    print(f"Errors: {len(errors)} files")

    if errors:
        print("\nFirst 10 errors:")
        for name, err in errors[:10]:
            print(f"  - {name}: {err}")

    if not valid_files:
        print("\nNo valid rules to compile!")
        return False

    # Compile all rules together
    print("\nCompiling all rules...")
    start = time.time()

    try:
        compiled = yara.compile(filepaths=valid_files)
        compile_time = time.time() - start
        print(f"Compilation time: {compile_time:.2f}s")

        # Save compiled rules
        output_file.parent.mkdir(parents=True, exist_ok=True)
        compiled.save(str(output_file))

        file_size = output_file.stat().st_size / 1024 / 1024
        print(f"Saved to: {output_file} ({file_size:.2f} MB)")

        # Test load time
        print("\nTesting load time...")
        start = time.time()
        yara.load(str(output_file))
        load_time = time.time() - start
        print(f"Load time: {load_time:.3f}s")

        return True

    except Exception as e:
        print(f"Compilation failed: {e}")
        return False


def main():
    # Default paths - use optimized rules for faster loading
    source_dir = Path("rules/yara_optimized")
    output_file = Path("rules/yara/compiled_rules.yarc")
    
    # Fall back to full rules if optimized doesn't exist
    if not source_dir.exists():
        source_dir = Path("rules/yara_full")

    # Parse arguments
    if len(sys.argv) >= 2:
        source_dir = Path(sys.argv[1])
    if len(sys.argv) >= 3:
        output_file = Path(sys.argv[2])

    if not source_dir.exists():
        print(f"Error: Source directory not found: {source_dir}")
        sys.exit(1)

    print("YARA Rules Compiler")
    print("=" * 40)

    success = compile_rules(source_dir, output_file)

    print()
    print("=" * 40)
    if success:
        print("✓ Compilation successful!")
    else:
        print("✗ Compilation failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
