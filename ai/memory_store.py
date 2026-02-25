"""Local memory store for agent context persistence."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any


class MemoryStore:
    """Local memory storage for analysis context.

    Stores findings, function analysis cache, and analysis state
    to enable context recovery after compression and incremental analysis.
    """

    def __init__(self, project_dir: str | Path, sample_hash: str):
        """Initialize memory store.

        Args:
            project_dir: Project root directory.
            sample_hash: SHA256 hash of the sample being analyzed.
        """
        self.sample_hash = sample_hash
        self.base_path = Path(project_dir) / ".threatscope" / "memory" / sample_hash
        self.base_path.mkdir(parents=True, exist_ok=True)

    def save_findings(self, findings: list[dict]) -> None:
        """Save key findings to persistent storage.

        Args:
            findings: List of finding dictionaries.
        """
        findings_file = self.base_path / "findings.json"
        data = {
            "version": "1.0",
            "sample_hash": self.sample_hash,
            "updated_at": datetime.now().isoformat(),
            "findings": findings,
        }
        findings_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def get_findings(self) -> list[dict]:
        """Get saved findings.

        Returns:
            List of finding dictionaries.
        """
        findings_file = self.base_path / "findings.json"
        if findings_file.exists():
            data = json.loads(findings_file.read_text())
            return data.get("findings", [])
        return []

    def add_finding(self, finding: dict) -> None:
        """Add a single finding.

        Args:
            finding: Finding dictionary with type, summary, evidence, severity.
        """
        findings = self.get_findings()
        finding["id"] = f"finding_{len(findings) + 1:03d}"
        finding["discovered_at"] = datetime.now().isoformat()
        findings.append(finding)
        self.save_findings(findings)

    def cache_function(self, name: str, analysis: dict) -> None:
        """Cache function analysis result.

        Args:
            name: Function name.
            analysis: Analysis result dictionary.
        """
        func_dir = self.base_path / "functions"
        func_dir.mkdir(exist_ok=True)

        # Sanitize function name for filename
        safe_name = name.replace("/", "_").replace("\\", "_")
        func_file = func_dir / f"{safe_name}.json"

        analysis["analyzed_at"] = datetime.now().isoformat()
        func_file.write_text(json.dumps(analysis, indent=2, ensure_ascii=False))

    def get_function(self, name: str) -> dict | None:
        """Get cached function analysis.

        Args:
            name: Function name.

        Returns:
            Analysis dictionary or None if not cached.
        """
        safe_name = name.replace("/", "_").replace("\\", "_")
        func_file = self.base_path / "functions" / f"{safe_name}.json"
        if func_file.exists():
            return json.loads(func_file.read_text())
        return None

    def list_cached_functions(self) -> list[str]:
        """List all cached function names.

        Returns:
            List of function names.
        """
        func_dir = self.base_path / "functions"
        if func_dir.exists():
            return [f.stem for f in func_dir.glob("*.json")]
        return []

    def save_checkpoint(self, state: dict) -> None:
        """Save analysis state checkpoint.

        Args:
            state: State dictionary with phase, summary, etc.
        """
        state_file = self.base_path / "analysis_state.json"
        state["last_checkpoint"] = datetime.now().isoformat()
        state["analyzed_functions"] = self.list_cached_functions()
        state_file.write_text(json.dumps(state, indent=2, ensure_ascii=False))

    def restore_checkpoint(self) -> dict | None:
        """Restore analysis state from checkpoint.

        Returns:
            State dictionary or None if no checkpoint exists.
        """
        state_file = self.base_path / "analysis_state.json"
        if state_file.exists():
            return json.loads(state_file.read_text())
        return None

    def save_iocs(self, iocs: dict[str, list[str]]) -> None:
        """Save discovered IoCs.

        Args:
            iocs: Dictionary with domains, ips, urls, hashes.
        """
        ioc_file = self.base_path / "iocs.json"
        data = {
            "updated_at": datetime.now().isoformat(),
            "iocs": iocs,
        }
        ioc_file.write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def get_iocs(self) -> dict[str, list[str]]:
        """Get saved IoCs.

        Returns:
            Dictionary with IoC lists.
        """
        ioc_file = self.base_path / "iocs.json"
        if ioc_file.exists():
            data = json.loads(ioc_file.read_text())
            return data.get("iocs", {})
        return {}

    def clear(self) -> None:
        """Clear all stored data for this sample."""
        import shutil
        if self.base_path.exists():
            shutil.rmtree(self.base_path)
