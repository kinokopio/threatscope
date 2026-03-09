"""Tests for static analysis tools."""

import tempfile
from pathlib import Path

import pytest

from src.threatscope.analysis.tools.static import HashCalculator


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

    @pytest.mark.asyncio
    async def test_calculate_hashes_nonexistent_file(self):
        """Test hash calculation on nonexistent file."""
        calculator = HashCalculator()
        result = await calculator.analyze(Path("/nonexistent/file"))

        assert not result.success
        assert result.error is not None
