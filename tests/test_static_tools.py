"""Tests for static analysis tools."""

import tempfile
from pathlib import Path

import pytest

from src.threatscope.analysis.tools.static import FunctionClassifier, HashCalculator, MitreMapper


class TestHashCalculator:
    """Tests for HashCalculator."""

    @pytest.mark.asyncio
    async def test_calculate_hashes(self):
        """Test hash calculation on a simple file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"test content")
            f.flush()

            calculator = HashCalculator()
            result = await calculator.analyze(Path(f.name))

            assert result.success
            assert "md5" in result.data
            assert "sha1" in result.data
            assert "sha256" in result.data
            assert len(result.data["md5"]) == 32
            assert len(result.data["sha256"]) == 64


class TestFunctionClassifier:
    """Tests for FunctionClassifier."""

    def test_classify_networking_functions(self):
        """Test classification of networking functions."""
        classifier = FunctionClassifier()
        functions = ["socket", "connect", "send", "recv", "printf"]

        result = classifier.classify_functions(functions)

        assert "Networking" in result
        assert "socket" in result["Networking"]
        assert "connect" in result["Networking"]

    def test_get_category_summary(self):
        """Test category summary generation."""
        classifier = FunctionClassifier()
        functions = ["socket", "connect", "dlopen", "dlsym", "ptrace"]

        summary = classifier.get_category_summary(functions)

        assert "classifications" in summary
        assert "risk_score" in summary
        assert summary["risk_score"] > 0


class TestMitreMapper:
    """Tests for MitreMapper."""

    def test_map_discovery_functions(self):
        """Test MITRE mapping for discovery functions."""
        mapper = MitreMapper()
        functions = ["uname", "gethostname", "getpid", "socket"]

        mappings = mapper.map_functions(functions)

        assert len(mappings) > 0
        tactics = {m["tactic"] for m in mappings}
        assert "Discovery" in tactics

    def test_get_mapping_summary(self):
        """Test mapping summary generation."""
        mapper = MitreMapper()
        functions = ["execve", "system", "dlopen", "socket", "connect"]

        summary = mapper.get_mapping_summary(functions)

        assert "tactics" in summary
        assert "techniques" in summary
        assert "risk_level" in summary
