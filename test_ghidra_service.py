#!/usr/bin/env python3
"""Test script for Ghidra service auto-start."""

import sys

sys.path.insert(0, ".")

from ghidra_service.manager import GhidraServiceManager


def main():
    print("Testing Ghidra Service Manager (Docker mode)...")

    manager = GhidraServiceManager(
        mode="docker",
        docker_image="threatscope-ghidra:latest",
        host="localhost",
        port=8080,
        startup_timeout=120,
    )

    print(f"Base URL: {manager.base_url}")
    print(f"Is running: {manager.is_running()}")

    print("\nStarting Ghidra service...")
    success = manager.start()

    if success:
        print("✅ Ghidra service started successfully!")
        print(f"Service URL: {manager.base_url}")

        # Test health endpoint
        import httpx

        try:
            resp = httpx.get(f"{manager.base_url}/health", timeout=5)
            print(f"Health check: {resp.json()}")
        except Exception as e:
            print(f"Health check failed: {e}")

        print("\nStopping service...")
        manager.stop()
        print("✅ Service stopped")
    else:
        print("❌ Failed to start Ghidra service")
        print("Check docker logs:")
        print("  docker logs ghidra-service-*")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
