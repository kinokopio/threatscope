"""
GhidraAnalyzer: Binary analysis using pyghidra.

Provides functions, strings, metadata, call graph, and decompilation.
Adapted from Phantom_TrojanWalker project.
"""

import logging
import os
import shutil
import tempfile
from typing import Any

logger = logging.getLogger(__name__)

# Lazy-loaded Ghidra/Java classes (populated after pyghidra.start())
_ghidra_started = False
_DecompInterface = None
_DecompileOptions = None
_ConsoleTaskMonitor = None
_StringDataInstance = None


def _ensure_ghidra_started():
    """Initialize pyghidra/JVM if not already started."""
    global _ghidra_started, _DecompInterface, _DecompileOptions
    global _ConsoleTaskMonitor, _StringDataInstance

    if _ghidra_started:
        return

    import pyghidra

    pyghidra.start()

    # Import Ghidra Java classes via JPype bridge
    from ghidra.app.decompiler import DecompileOptions, DecompInterface
    from ghidra.program.model.data import StringDataInstance
    from ghidra.util.task import ConsoleTaskMonitor

    _DecompInterface = DecompInterface
    _DecompileOptions = DecompileOptions
    _ConsoleTaskMonitor = ConsoleTaskMonitor
    _StringDataInstance = StringDataInstance
    _ghidra_started = True
    logger.info("Ghidra/pyghidra initialized successfully")


class GhidraAnalyzer:
    """Analyzer class for binary files using Ghidra/pyghidra."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self._ctx = None
        self._flat_api = None
        self._program = None
        self._decompiler = None
        self._project_dir = None

    def open(self) -> bool:
        """Initialize Ghidra and open the binary file."""
        try:
            _ensure_ghidra_started()
            import pyghidra

            self._project_dir = tempfile.mkdtemp(prefix="ghidra_project_")
            self._ctx = pyghidra.open_program(
                self.file_path,
                analyze=False,
                project_location=self._project_dir,
                project_name="TempProject",
            )
            self._flat_api = self._ctx.__enter__()
            self._program = self._flat_api.getCurrentProgram()

            # Initialize decompiler
            self._decompiler = _DecompInterface()
            options = _DecompileOptions()
            options.setWARNCommentIncluded(False)
            options.setHeadCommentIncluded(False)
            options.setPLATECommentIncluded(False)
            options.setPRECommentIncluded(False)
            options.setPOSTCommentIncluded(False)
            options.setEOLCommentIncluded(False)
            self._decompiler.setOptions(options)
            self._decompiler.openProgram(self._program)

            logger.info(f"Opened binary: {self.file_path}")
            return True

        except Exception as e:
            logger.error(f"Error opening binary with Ghidra: {e}")
            return False

    def analyze(self) -> dict[str, str]:
        """Execute Ghidra auto-analysis on the binary."""
        if not self._program:
            return {"status": "error", "message": "Program not opened"}

        try:
            self._flat_api.analyzeAll(self._program)
            logger.info("Ghidra analysis completed")
            return {"status": "done"}
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {"status": "error", "message": str(e)}

    def get_functions(self, offset: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        """Get list of functions with pagination."""
        if not self._program:
            return []

        functions = []
        try:
            func_manager = self._program.getFunctionManager()
            for i, func in enumerate(func_manager.getFunctions(True)):
                if i < offset:
                    continue
                if len(functions) >= limit:
                    break

                entry = func.getEntryPoint()
                body = func.getBody()
                functions.append(
                    {
                        "name": func.getName(),
                        "address": str(entry) if entry else "",
                        "offset": entry.getOffset() if entry else 0,
                        "size": body.getNumAddresses() if body else 0,
                        "signature": (
                            func.getSignature().getPrototypeString() if func.getSignature() else ""
                        ),
                    }
                )

            logger.info(f"Found {len(functions)} functions (offset={offset})")
            return functions

        except Exception as e:
            logger.error(f"Error getting functions: {e}")
            return []

    def get_function_details(self, target: str) -> dict[str, Any] | None:
        """Get detailed information about a function."""
        func = self._find_function(target)
        if not func:
            return None

        try:
            entry = func.getEntryPoint()
            body = func.getBody()
            stack_frame = func.getStackFrame()

            return {
                "name": func.getName(),
                "address": str(entry) if entry else "",
                "offset": entry.getOffset() if entry else 0,
                "size": body.getNumAddresses() if body else 0,
                "signature": (
                    func.getSignature().getPrototypeString() if func.getSignature() else ""
                ),
                "calling_convention": str(func.getCallingConventionName()),
                "is_thunk": func.isThunk(),
                "is_external": func.isExternal(),
                "stack_frame_size": stack_frame.getFrameSize() if stack_frame else 0,
                "parameter_count": func.getParameterCount(),
                "local_variable_count": len(list(func.getLocalVariables())),
            }
        except Exception as e:
            logger.error(f"Error getting function details: {e}")
            return None

    def get_strings(self, min_length: int = 4) -> list[dict[str, Any]]:
        """Get strings from the binary."""
        if not self._program:
            return []

        strings = []
        try:
            listing = self._program.getListing()
            for data in listing.getDefinedData(True):
                type_name = self._get_data_type_name(data)
                if not self._is_string_type(type_name):
                    continue

                str_value = self._safe_string_value(data)
                if not str_value or len(str_value) < min_length:
                    continue

                addr = data.getAddress()
                strings.append(
                    {
                        "address": str(addr) if addr else "",
                        "offset": addr.getOffset() if addr else 0,
                        "value": str_value,
                        "type": type_name,
                        "length": len(str_value),
                    }
                )

            logger.info(f"Found {len(strings)} strings")
            return strings

        except Exception as e:
            logger.error(f"Error getting strings: {e}")
            return []

    def search_strings(self, pattern: str, max_results: int = 100) -> list[dict]:
        """Search strings matching a regex pattern."""
        import re

        if not self._program:
            return []

        results = []
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            listing = self._program.getListing()

            for data in listing.getDefinedData(True):
                if len(results) >= max_results:
                    break

                type_name = self._get_data_type_name(data)
                if not self._is_string_type(type_name):
                    continue

                str_value = self._safe_string_value(data)
                if str_value and regex.search(str_value):
                    addr = data.getAddress()
                    results.append(
                        {
                            "address": str(addr) if addr else "",
                            "value": str_value,
                        }
                    )

            return results

        except Exception as e:
            logger.error(f"Error searching strings: {e}")
            return []

    def decompile_function(self, target: str) -> dict[str, str] | None:
        """Decompile a function by name or address."""
        if not self._program or not self._decompiler:
            return None

        try:
            func = self._find_function(target)
            if not func:
                return None

            monitor = _ConsoleTaskMonitor()
            results = self._decompiler.decompileFunction(func, 60, monitor)

            if results and results.decompileCompleted():
                decomp_func = results.getDecompiledFunction()
                if decomp_func:
                    return {
                        "name": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "code": decomp_func.getC(),
                    }

            return None

        except Exception as e:
            logger.error(f"Error decompiling {target}: {e}")
            return None

    def decompile_batch(self, targets: list[str]) -> list[dict[str, str]]:
        """Batch decompile multiple functions."""
        if not self._program or not self._decompiler:
            return []

        results = []
        monitor = _ConsoleTaskMonitor()

        for target in targets:
            try:
                func = self._find_function(target)
                if not func:
                    continue

                decomp_results = self._decompiler.decompileFunction(func, 60, monitor)
                if decomp_results and decomp_results.decompileCompleted():
                    decomp_func = decomp_results.getDecompiledFunction()
                    if decomp_func and decomp_func.getC():
                        results.append(
                            {
                                "name": func.getName(),
                                "address": str(func.getEntryPoint()),
                                "code": decomp_func.getC(),
                            }
                        )

            except Exception as e:
                logger.warning(f"Error decompiling {target}: {e}")

        logger.info(f"Decompiled {len(results)}/{len(targets)} functions")
        return results

    def disassemble_function(
        self, target: str, max_instructions: int = 100
    ) -> dict[str, Any] | None:
        """Get assembly instructions for a function."""
        func = self._find_function(target)
        if not func:
            return None

        try:
            listing = self._program.getListing()
            instructions = []

            for instr in listing.getInstructions(func.getBody(), True):
                if len(instructions) >= max_instructions:
                    break

                instr_bytes = instr.getBytes()
                instructions.append(
                    {
                        "address": str(instr.getAddress()),
                        "mnemonic": instr.getMnemonicString(),
                        "operands": str(instr),
                        "bytes": instr_bytes.hex() if instr_bytes else "",
                    }
                )

            return {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "instruction_count": len(instructions),
                "instructions": instructions,
            }

        except Exception as e:
            logger.error(f"Error disassembling {target}: {e}")
            return None

    def get_function_xrefs(self, target: str) -> dict[str, Any] | None:
        """Get cross-references for a function."""
        if not self._program:
            return None

        try:
            func = self._find_function(target)
            if not func:
                return None

            func_manager = self._program.getFunctionManager()
            ref_manager = self._program.getReferenceManager()

            return {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "offset": func.getEntryPoint().getOffset(),
                "callers": self._get_callers(func, func_manager, ref_manager),
                "callees": self._get_callees(func, func_manager, ref_manager),
            }

        except Exception as e:
            logger.error(f"Error getting xrefs for {target}: {e}")
            return None

    def get_callgraph(self, target: str, max_depth: int = 3) -> dict[str, Any] | None:
        """Get call graph starting from a function."""
        func = self._find_function(target)
        if not func:
            return None

        try:
            func_manager = self._program.getFunctionManager()
            ref_manager = self._program.getReferenceManager()

            def build_graph(f, depth, visited):
                if depth <= 0 or f.getName() in visited:
                    return {}
                visited.add(f.getName())

                result = {}
                body = f.getBody()
                if body:
                    for ref in self._iter_call_refs(body, ref_manager):
                        callee = func_manager.getFunctionAt(ref.getToAddress())
                        if callee and callee.getName() not in visited:
                            result[callee.getName()] = build_graph(callee, depth - 1, visited)
                return result

            visited = set()
            return {
                "root": func.getName(),
                "max_depth": max_depth,
                "callgraph": {func.getName(): build_graph(func, max_depth, visited)},
            }

        except Exception as e:
            logger.error(f"Error building callgraph: {e}")
            return None

    def get_global_callgraph(self) -> dict[str, Any]:
        """Generate global call graph with all functions."""
        if not self._program:
            return {}

        try:
            func_manager = self._program.getFunctionManager()
            ref_manager = self._program.getReferenceManager()

            nodes = []
            edges = []
            func_map = {}

            # Collect nodes
            for idx, func in enumerate(func_manager.getFunctions(True)):
                name = func.getName()
                entry = func.getEntryPoint()
                nodes.append(
                    {
                        "id": idx,
                        "name": name,
                        "offset": entry.getOffset() if entry else 0,
                    }
                )
                func_map[name] = idx

            # Collect edges
            for func in func_manager.getFunctions(True):
                caller_name = func.getName()
                if caller_name not in func_map:
                    continue

                body = func.getBody()
                if not body:
                    continue

                called = set()
                for ref in self._iter_call_refs(body, ref_manager):
                    callee = func_manager.getFunctionAt(ref.getToAddress())
                    if callee:
                        called.add(callee.getName())

                for callee_name in called:
                    if callee_name in func_map:
                        edges.append(
                            {
                                "from": func_map[caller_name],
                                "to": func_map[callee_name],
                            }
                        )

            logger.info(f"Call graph: {len(nodes)} nodes, {len(edges)} edges")
            return {"nodes": nodes, "edges": edges}

        except Exception as e:
            logger.error(f"Error generating call graph: {e}")
            return {}

    def read_memory(self, address: str, length: int = 256) -> dict[str, Any] | None:
        """Read memory at specified address."""
        if not self._program:
            return None

        try:
            addr = self._program.getAddressFactory().getAddress(address)
            memory = self._program.getMemory()

            data = bytearray(length)
            bytes_read = memory.getBytes(addr, data)

            return {
                "address": address,
                "length": bytes_read,
                "hex": data[:bytes_read].hex(),
                "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data[:bytes_read]),
            }

        except Exception as e:
            logger.error(f"Error reading memory: {e}")
            return None

    def get_imports(self) -> list[dict[str, Any]]:
        """Get imported functions."""
        if not self._program:
            return []

        imports = []
        try:
            func_manager = self._program.getFunctionManager()
            for func in func_manager.getExternalFunctions():
                ext_loc = func.getExternalLocation()
                imports.append(
                    {
                        "name": func.getName(),
                        "address": str(func.getEntryPoint()),
                        "library": str(ext_loc.getLibraryName()) if ext_loc else "",
                    }
                )
            return imports

        except Exception as e:
            logger.error(f"Error getting imports: {e}")
            return []

    def get_exports(self) -> list[dict[str, Any]]:
        """Get exported symbols."""
        if not self._program:
            return []

        exports = []
        try:
            symbol_table = self._program.getSymbolTable()
            for symbol in symbol_table.getAllSymbols(True):
                if symbol.isExternalEntryPoint():
                    exports.append(
                        {
                            "name": symbol.getName(),
                            "address": str(symbol.getAddress()),
                        }
                    )
            return exports

        except Exception as e:
            logger.error(f"Error getting exports: {e}")
            return []

    def get_sections(self) -> list[dict[str, Any]]:
        """Get program sections/segments."""
        if not self._program:
            return []

        sections = []
        try:
            memory = self._program.getMemory()
            for block in memory.getBlocks():
                sections.append(
                    {
                        "name": block.getName(),
                        "start": str(block.getStart()),
                        "end": str(block.getEnd()),
                        "size": block.getSize(),
                        "permissions": {
                            "read": block.isRead(),
                            "write": block.isWrite(),
                            "execute": block.isExecute(),
                        },
                        "initialized": block.isInitialized(),
                    }
                )
            return sections

        except Exception as e:
            logger.error(f"Error getting sections: {e}")
            return []

    def get_info(self) -> dict[str, Any]:
        """Get binary metadata."""
        if not self._program:
            return {}

        try:
            lang = self._program.getLanguage()
            compiler_spec = self._program.getCompilerSpec()
            exe_format = self._program.getExecutableFormat()

            file_size = None
            human_size = None
            try:
                file_size = os.path.getsize(self.file_path)
                human_size = self._format_size(file_size)
            except Exception:
                pass

            return {
                "file": os.path.basename(self.file_path),
                "format": exe_format or "unknown",
                "arch": str(lang.getProcessor()) if lang else "unknown",
                "bits": lang.getLanguageDescription().getSize() if lang else 0,
                "endian": (
                    "little"
                    if (lang and not lang.isBigEndian())
                    else ("big" if lang else "unknown")
                ),
                "compiler": (
                    compiler_spec.getCompilerSpecID().getIdAsString()
                    if compiler_spec
                    else "unknown"
                ),
                "size": file_size,
                "human_size": human_size,
            }

        except Exception as e:
            logger.error(f"Error getting info: {e}")
            return {}

    def close(self):
        """Close analyzer and release resources."""
        try:
            if self._decompiler:
                self._decompiler.closeProgram()
                self._decompiler.dispose()
                self._decompiler = None

            if self._ctx:
                try:
                    self._ctx.__exit__(None, None, None)
                except Exception:
                    pass
                self._ctx = None
                self._flat_api = None

            self._program = None

            if self._project_dir and os.path.exists(self._project_dir):
                try:
                    shutil.rmtree(self._project_dir)
                except Exception:
                    pass
                self._project_dir = None

            logger.info("GhidraAnalyzer closed")

        except Exception as e:
            logger.error(f"Error closing analyzer: {e}")

    # --- Internal helpers ---

    def _find_function(self, target: str) -> Any | None:
        """Find function by name or address."""
        if not self._program:
            return None

        func_manager = self._program.getFunctionManager()

        # Try as address
        addr_val = self._parse_address(target)
        if addr_val is not None:
            addr_factory = self._program.getAddressFactory()
            addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val)
            func = func_manager.getFunctionAt(addr)
            if func:
                return func
            func = func_manager.getFunctionContaining(addr)
            if func:
                return func

        # Try by name
        for func in func_manager.getFunctions(True):
            if func.getName() == target:
                return func
            if func.getName().lower() == target.lower():
                return func

        return None

    def _parse_address(self, value: str) -> int | None:
        """Parse address string to integer."""
        try:
            if value.startswith("0x"):
                return int(value, 16)
            if value.startswith("FUN_"):
                return int(value[4:], 16)
            if value.startswith("thunk_FUN_"):
                return int(value[10:], 16)
        except (ValueError, Exception):
            pass
        return None

    def _get_callees(self, func, func_manager, ref_manager) -> list[dict]:
        """Get functions called by this function."""
        callees = []
        seen = set()

        body = func.getBody()
        if not body:
            return callees

        for ref in self._iter_call_refs(body, ref_manager):
            callee = func_manager.getFunctionAt(ref.getToAddress())
            if callee and callee.getName() not in seen:
                seen.add(callee.getName())
                entry = callee.getEntryPoint()
                callees.append(
                    {
                        "name": callee.getName(),
                        "offset": entry.getOffset() if entry else 0,
                    }
                )

        return callees

    def _get_callers(self, func, func_manager, ref_manager) -> list[dict]:
        """Get functions that call this function."""
        callers = []
        seen = set()

        entry = func.getEntryPoint()
        if not entry:
            return callers

        for ref in ref_manager.getReferencesTo(entry):
            if hasattr(ref, "getReferenceType"):
                if not ref.getReferenceType().isCall():
                    continue
                from_addr = ref.getFromAddress()
            else:
                continue

            caller = func_manager.getFunctionContaining(from_addr)
            if caller and caller.getName() not in seen:
                seen.add(caller.getName())
                caller_entry = caller.getEntryPoint()
                callers.append(
                    {
                        "name": caller.getName(),
                        "offset": caller_entry.getOffset() if caller_entry else 0,
                    }
                )

        return callers

    def _iter_call_refs(self, body, ref_manager):
        """Iterate call references from function body."""
        if not body:
            return

        try:
            ref_iter = ref_manager.getReferenceSourceIterator(body, True)
        except Exception:
            return

        for from_addr in ref_iter:
            try:
                for ref in ref_manager.getReferencesFrom(from_addr):
                    if ref.getReferenceType().isCall():
                        yield ref
            except Exception:
                continue

    def _get_data_type_name(self, data) -> str:
        """Get data type name."""
        data_type = data.getDataType()
        return data_type.getName().lower() if data_type else ""

    def _is_string_type(self, type_name: str) -> bool:
        """Check if type is a string type."""
        return "string" in type_name or "unicode" in type_name

    def _safe_string_value(self, data) -> str:
        """Safely extract string value."""
        try:
            value = data.getValue()
            return str(value) if value else ""
        except Exception:
            return ""

    def _format_size(self, size: int) -> str:
        """Format file size to human readable."""
        units = ["B", "KB", "MB", "GB"]
        for unit in units[:-1]:
            if size < 1024:
                return f"{size:.1f}{unit}" if unit != "B" else f"{size}{unit}"
            size /= 1024
        return f"{size:.1f}{units[-1]}"

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
