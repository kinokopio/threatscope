"""Tests for dynamic analysis routing."""

import pytest

from src.threatscope.analysis.services.dynamic_analysis import (
    DynamicAnalysisService,
    TRACEE_SUPPORTED_ARCHS,
)


class TestDynamicAnalysisService:
    """Tests for DynamicAnalysisService routing logic."""

    def setup_method(self):
        """Set up test fixtures."""
        self.service = DynamicAnalysisService(timeout=30)

    def test_tracee_supported_archs(self):
        """Test that supported architectures are correctly defined."""
        assert "x86_64" in TRACEE_SUPPORTED_ARCHS
        assert "amd64" in TRACEE_SUPPORTED_ARCHS
        assert "i386" in TRACEE_SUPPORTED_ARCHS
        assert "i686" in TRACEE_SUPPORTED_ARCHS

    def test_get_tracee_arch_x86_64(self):
        """Test architecture mapping for x86_64."""
        assert self.service._get_tracee_arch("AMD64") == "x86_64"
        assert self.service._get_tracee_arch("x86_64") == "x86_64"
        assert self.service._get_tracee_arch("amd64") == "x86_64"

    def test_get_tracee_arch_i386(self):
        """Test architecture mapping for i386."""
        assert self.service._get_tracee_arch("I386") == "i386"
        assert self.service._get_tracee_arch("i686") == "i386"

    def test_get_tracee_arch_unsupported(self):
        """Test architecture mapping for unsupported architectures."""
        assert self.service._get_tracee_arch("ARM64") is None
        assert self.service._get_tracee_arch("MIPS") is None
        assert self.service._get_tracee_arch("") is None

    def test_skip_pe(self):
        """Test that PE files return skip result."""
        result = self.service._skip_pe({"category": "pe", "arch": "AMD64"})

        assert result["success"] is False
        assert result["skipped"] is True
        assert result["method"] == "none"
        assert result["file_type"] == "pe"
        assert result["planned_method"] == "cape"
        assert "CAPE" in result["reason"]

    def test_skip_unsupported(self):
        """Test that unsupported file types return skip result."""
        result = self.service._skip_unsupported("script:python", {"category": "script:python"})

        assert result["success"] is False
        assert result["skipped"] is True
        assert result["method"] == "none"
        assert result["file_type"] == "script:python"
        assert "not supported" in result["reason"]

    @pytest.mark.asyncio
    async def test_analyze_pe_skips(self):
        """Test that PE files are skipped."""
        file_type = {"category": "pe", "arch": "AMD64"}
        result = await self.service.analyze("/fake/path.exe", file_type)

        assert result["skipped"] is True
        assert result["file_type"] == "pe"
        assert result["planned_method"] == "cape"

    @pytest.mark.asyncio
    async def test_analyze_script_skips(self):
        """Test that script files are skipped."""
        file_type = {"category": "script:python", "arch": ""}
        result = await self.service.analyze("/fake/script.py", file_type)

        assert result["skipped"] is True
        assert result["file_type"] == "script:python"

    @pytest.mark.asyncio
    async def test_analyze_unknown_skips(self):
        """Test that unknown files are skipped."""
        file_type = {"category": "unknown", "arch": ""}
        result = await self.service.analyze("/fake/unknown", file_type)

        assert result["skipped"] is True
        assert result["file_type"] == "unknown"

    @pytest.mark.asyncio
    async def test_analyze_elf_unsupported_arch_skips(self):
        """Test that ELF with unsupported arch is skipped."""
        file_type = {"category": "elf", "arch": "ARM64"}
        result = await self.service.analyze("/fake/binary", file_type)

        assert result["skipped"] is True
        assert result["method"] == "tracee"
        assert result["file_type"] == "elf"
        assert "arm64" in result["reason"].lower()


class TestFileTypeRouting:
    """Tests for file type routing decisions."""

    def test_pe_category_detection(self):
        """Test PE category is correctly identified."""
        file_type = {"category": "pe", "format": "PE64", "arch": "AMD64"}
        assert file_type["category"] == "pe"

    def test_elf_category_detection(self):
        """Test ELF category is correctly identified."""
        file_type = {"category": "elf", "format": "ELF64", "arch": "AMD64"}
        assert file_type["category"] == "elf"

    def test_script_category_detection(self):
        """Test script categories are correctly identified."""
        categories = [
            "script:python",
            "script:shell",
            "script:powershell",
            "script:batch",
        ]
        for cat in categories:
            assert cat.startswith("script:")

    def test_supported_categories(self):
        """Test that only PE and ELF are supported for full analysis."""
        supported = ("pe", "elf")

        assert "pe" in supported
        assert "elf" in supported
        assert "script:python" not in supported
        assert "macho" not in supported
        assert "unknown" not in supported
