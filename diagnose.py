#!/usr/bin/env python3
"""Diagnostic script for ThreatScope backend issues."""

import sys
import time
import asyncio


def check_imports():
    """Check if all required modules can be imported."""
    print("=== Checking imports ===")
    modules = [
        ("fastapi", "FastAPI"),
        ("uvicorn", "Uvicorn"),
        ("yara", "YARA"),
        ("lief", "LIEF"),
        ("anthropic", "Anthropic"),
        ("docker", "Docker SDK"),
    ]

    for module, name in modules:
        try:
            __import__(module)
            print(f"  ✓ {name}")
        except ImportError as e:
            print(f"  ✗ {name}: {e}")


def check_database():
    """Check database connectivity."""
    print("\n=== Checking database ===")
    try:
        from core.database import get_database

        db = get_database()
        stats = db.get_stats()
        print(f"  ✓ Database connected")
        print(f"    Total tasks: {stats.get('total', 0)}")
    except Exception as e:
        print(f"  ✗ Database error: {e}")


def check_yara_rules():
    """Check YARA rules loading."""
    print("\n=== Checking YARA rules ===")
    try:
        from pathlib import Path
        import yara

        rules_path = Path("rules/yara")
        if not rules_path.exists():
            print(f"  ✗ Rules directory not found: {rules_path}")
            return

        rule_files = list(rules_path.glob("*.yar"))
        print(f"  Found {len(rule_files)} rule files")

        start = time.time()
        loaded = 0
        errors = 0
        for rf in rule_files:
            try:
                yara.compile(filepath=str(rf))
                loaded += 1
            except:
                errors += 1

        elapsed = time.time() - start
        print(f"  ✓ Loaded {loaded} files in {elapsed:.2f}s")
        if errors:
            print(f"  ⚠ {errors} files had errors")
    except Exception as e:
        print(f"  ✗ YARA error: {e}")


def check_coordinator():
    """Check coordinator initialization."""
    print("\n=== Checking coordinator ===")
    try:
        from core.coordinator import AnalysisCoordinator

        start = time.time()
        coord = AnalysisCoordinator()
        elapsed = time.time() - start
        print(f"  ✓ Coordinator initialized in {elapsed:.2f}s")
    except Exception as e:
        print(f"  ✗ Coordinator error: {e}")
        import traceback

        traceback.print_exc()


async def check_api_startup():
    """Check API startup."""
    print("\n=== Checking API startup ===")
    try:
        from api.rest import app, get_scheduled_coordinator

        print("  Getting scheduled coordinator...")
        start = time.time()
        scheduler = get_scheduled_coordinator()
        print(f"  ✓ Scheduler created in {time.time() - start:.2f}s")

        print("  Starting scheduler...")
        start = time.time()
        await scheduler.start()
        print(f"  ✓ Scheduler started in {time.time() - start:.2f}s")

        await scheduler.stop()
        print("  ✓ Scheduler stopped")
    except Exception as e:
        print(f"  ✗ API startup error: {e}")
        import traceback

        traceback.print_exc()


def check_qemu_docker():
    """Check QEMU and Docker availability."""
    print("\n=== Checking QEMU/Docker ===")
    import shutil
    import subprocess

    # Check QEMU
    qemu_bins = ["qemu-x86_64-static", "qemu-x86_64", "qemu-aarch64-static"]
    for qemu in qemu_bins:
        path = shutil.which(qemu)
        if path:
            print(f"  ✓ {qemu}: {path}")
        else:
            print(f"  ✗ {qemu}: not found")

    # Check Docker
    docker = shutil.which("docker")
    if docker:
        try:
            result = subprocess.run(["docker", "ps"], capture_output=True, timeout=5)
            if result.returncode == 0:
                print(f"  ✓ Docker: running")
            else:
                print(f"  ⚠ Docker: installed but not running")
        except:
            print(f"  ⚠ Docker: installed but error checking status")
    else:
        print(f"  ✗ Docker: not found")


def main():
    print("ThreatScope Diagnostic Tool")
    print("=" * 40)

    check_imports()
    check_database()
    check_yara_rules()
    check_coordinator()
    check_qemu_docker()

    print("\n=== Checking async startup ===")
    asyncio.run(check_api_startup())

    print("\n" + "=" * 40)
    print("Diagnostic complete!")


if __name__ == "__main__":
    main()
