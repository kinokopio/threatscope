"""Ghidra HTTP client for communicating with Ghidra service."""

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class GhidraClient:
    """HTTP client for Ghidra service."""

    def __init__(self, base_url: str = "http://localhost:8000", timeout: float = 120):
        """Initialize Ghidra client.

        Args:
            base_url: Ghidra HTTP service URL
            timeout: Request timeout in seconds
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _request(
        self,
        method: str,
        path: str,
        params: dict | None = None,
        json: Any = None,
        files: dict | None = None,
    ) -> Any:
        """Make HTTP request to Ghidra service."""
        url = f"{self.base_url}{path}"
        try:
            response = httpx.request(
                method,
                url,
                params=params,
                json=json,
                files=files,
                timeout=self.timeout,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 409:
                raise RuntimeError("No binary loaded. Upload first.") from e
            if e.response.status_code == 404:
                raise RuntimeError(f"Not found: {path}") from e
            raise RuntimeError(f"Ghidra error: {e.response.text}") from e
        except httpx.HTTPError as e:
            raise RuntimeError(f"Connection error: {e}") from e

    # --- Lifecycle ---

    def health_check(self) -> dict:
        """Check service health."""
        return self._request("GET", "/health")

    def upload(self, file_path: str) -> dict:
        """Upload binary file for analysis."""
        with open(file_path, "rb") as f:
            return self._request("POST", "/upload", files={"file": f})

    def close(self) -> dict:
        """Close current binary."""
        return self._request("POST", "/close")

    def analyze(self) -> dict:
        """Run Ghidra auto-analysis."""
        return self._request("POST", "/analyze")

    def get_info(self) -> dict:
        """Get binary metadata."""
        return self._request("GET", "/info")

    # --- Functions ---

    def list_functions(self, offset: int = 0, limit: int = 100) -> list[dict]:
        """Get function list."""
        return self._request("GET", "/functions", params={"offset": offset, "limit": limit})

    def get_function_details(self, target: str) -> dict:
        """Get function details."""
        return self._request("GET", f"/functions/{target}")

    def decompile_function(self, target: str) -> dict:
        """Decompile a function."""
        return self._request("GET", f"/functions/{target}/decompile")

    def disassemble_function(self, target: str, max_instructions: int = 100) -> dict:
        """Get assembly for a function."""
        return self._request(
            "GET",
            f"/functions/{target}/disassemble",
            params={"max_instructions": max_instructions},
        )

    def get_function_xrefs(self, target: str) -> dict:
        """Get cross-references for a function."""
        return self._request("GET", f"/functions/{target}/xrefs")

    def get_callgraph(self, target: str, max_depth: int = 3) -> dict:
        """Get call graph from a function."""
        return self._request(
            "GET", f"/functions/{target}/callgraph", params={"max_depth": max_depth}
        )

    def decompile_batch(self, targets: list[str]) -> list[dict]:
        """Batch decompile functions."""
        return self._request("POST", "/functions/decompile_batch", json=targets)

    # --- Strings ---

    def list_strings(self, min_length: int = 4) -> list[dict]:
        """Get strings from binary."""
        return self._request("GET", "/strings", params={"min_length": min_length})

    def search_strings(self, pattern: str, max_results: int = 100) -> list[dict]:
        """Search strings by pattern."""
        return self._request(
            "GET",
            "/strings/search",
            params={"pattern": pattern, "max_results": max_results},
        )

    # --- Structure ---

    def get_global_callgraph(self) -> dict:
        """Get global call graph."""
        return self._request("GET", "/callgraph")

    def read_memory(self, address: str, length: int = 256) -> dict:
        """Read memory at address."""
        return self._request("GET", f"/memory/{address}", params={"length": length})

    def get_imports(self) -> list[dict]:
        """Get imported functions."""
        return self._request("GET", "/imports")

    def get_exports(self) -> list[dict]:
        """Get exported symbols."""
        return self._request("GET", "/exports")

    def get_sections(self) -> list[dict]:
        """Get program sections."""
        return self._request("GET", "/sections")
