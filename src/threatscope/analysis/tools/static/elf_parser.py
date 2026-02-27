"""ELF binary parser using LIEF."""

from pathlib import Path

from src.threatscope.analysis.tools.base import AnalysisTool, ToolResult

try:
    import lief

    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False


class ELFParser(AnalysisTool):
    @property
    def name(self) -> str:
        return "elf_parser"

    async def analyze(self, file_path: Path) -> ToolResult:
        if not LIEF_AVAILABLE:
            return ToolResult(success=False, error="LIEF not installed")

        try:
            binary = lief.parse(str(file_path))
            if binary is None:
                return ToolResult(success=False, error="Failed to parse file")

            if not isinstance(binary, lief.ELF.Binary):
                return ToolResult(success=False, error="Not an ELF file")

            header = binary.header
            data = {
                "format": "ELF",
                "arch": str(header.machine_type).split(".")[-1],
                "bits": 64 if header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32,
                "endian": "little"
                if header.identity_data == lief.ELF.Header.ELF_DATA.LSB
                else "big",
                "type": str(header.file_type).split(".")[-1],
                "entry_point": hex(binary.entrypoint),
            }

            sections = []
            for section in binary.sections:
                sections.append(
                    {
                        "name": section.name,
                        "type": str(section.type).split(".")[-1],
                        "size": section.size,
                        "entropy": round(section.entropy, 2),
                        "flags": [str(f).split(".")[-1] for f in section.flags_list],
                    }
                )
            data["sections"] = sections

            segments = []
            for segment in binary.segments:
                segments.append(
                    {
                        "type": str(segment.type).split(".")[-1],
                        "flags": str(segment.flags).split(".")[-1],
                        "file_size": segment.physical_size,
                        "mem_size": segment.virtual_size,
                    }
                )
            data["segments"] = segments

            imports = [func.name for func in binary.imported_functions]
            data["imports"] = imports

            exports = [func.name for func in binary.exported_functions]
            data["exports"] = exports

            libraries = []
            for entry in binary.dynamic_entries:
                if entry.tag in (lief.ELF.DynamicEntry.TAG.NEEDED,):
                    libraries.append(str(entry.name))
            data["libraries"] = libraries

            data["security"] = {
                "nx": binary.has_nx,
                "pie": binary.is_pie,
                "relro": str(binary.relro).split(".")[-1] if hasattr(binary, "relro") else "NONE",
            }

            return ToolResult(success=True, data=data)

        except Exception as e:
            return ToolResult(success=False, error=str(e))
