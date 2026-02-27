"""Static analysis tools."""

from src.threatscope.analysis.tools.static.elf_parser import ELFParser
from src.threatscope.analysis.tools.static.function_classifier import FunctionClassifier
from src.threatscope.analysis.tools.static.hash_calculator import HashCalculator
from src.threatscope.analysis.tools.static.mitre_mapper import MitreMapper
from src.threatscope.analysis.tools.static.string_extractor import StringExtractor
from src.threatscope.analysis.tools.static.yara_scanner import YaraScanner

__all__ = [
    "HashCalculator",
    "StringExtractor",
    "ELFParser",
    "YaraScanner",
    "FunctionClassifier",
    "MitreMapper",
]
