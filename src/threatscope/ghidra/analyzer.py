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

    def get_function_xrefs_batch(self, targets: list[str]) -> list[dict[str, Any]]:
        """Batch get cross-references for multiple functions.

        Args:
            targets: List of function names or addresses.

        Returns:
            List of xref results for each found function.
        """
        if not self._program:
            return []

        results = []
        func_manager = self._program.getFunctionManager()
        ref_manager = self._program.getReferenceManager()

        for target in targets:
            try:
                func = self._find_function(target)
                if not func:
                    continue

                entry = func.getEntryPoint()
                results.append(
                    {
                        "name": func.getName(),
                        "address": str(entry) if entry else "",
                        "offset": entry.getOffset() if entry else 0,
                        "callers": self._get_callers(func, func_manager, ref_manager),
                        "callees": self._get_callees(func, func_manager, ref_manager),
                    }
                )
            except Exception as e:
                logger.warning(f"Error getting xrefs for {target}: {e}")

        logger.info(f"Got xrefs for {len(results)}/{len(targets)} functions")
        return results

    def get_functions_with_callers(
        self, min_callers: int = 1, limit: int = 100
    ) -> list[dict[str, Any]]:
        """Get functions that have at least min_callers callers.

        This filters out orphan functions (like thunks or unreferenced code)
        to focus analysis on functions that are actually called.

        Args:
            min_callers: Minimum number of callers required.
            limit: Maximum number of functions to return.

        Returns:
            List of functions with caller count.
        """
        if not self._program:
            return []

        results = []
        try:
            func_manager = self._program.getFunctionManager()
            ref_manager = self._program.getReferenceManager()

            for func in func_manager.getFunctions(True):
                if len(results) >= limit:
                    break

                entry = func.getEntryPoint()
                if not entry:
                    continue

                # Count callers
                caller_count = 0
                for ref in ref_manager.getReferencesTo(entry):
                    if hasattr(ref, "getReferenceType") and ref.getReferenceType().isCall():
                        caller_count += 1
                        if caller_count >= min_callers:
                            break

                if caller_count >= min_callers:
                    body = func.getBody()
                    results.append(
                        {
                            "name": func.getName(),
                            "address": str(entry),
                            "offset": entry.getOffset(),
                            "size": body.getNumAddresses() if body else 0,
                            "caller_count": caller_count,
                            "is_thunk": func.isThunk(),
                            "is_external": func.isExternal(),
                        }
                    )

            logger.info(f"Found {len(results)} functions with >= {min_callers} callers")
            return results

        except Exception as e:
            logger.error(f"Error getting functions with callers: {e}")
            return []

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

    def get_entry_points(self) -> list[dict[str, Any]]:
        """Get program entry points."""
        if not self._program:
            return []

        entry_points = []
        try:
            symbol_table = self._program.getSymbolTable()
            func_manager = self._program.getFunctionManager()

            # Get external entry points
            for symbol in symbol_table.getExternalEntryPointIterator():
                addr = symbol.getAddress()
                func = func_manager.getFunctionAt(addr)
                entry_points.append(
                    {
                        "name": symbol.getName(),
                        "address": str(addr),
                        "offset": addr.getOffset() if addr else 0,
                        "is_function": func is not None,
                        "type": "export",
                    }
                )

            # Also check for common entry point names
            common_entries = ["main", "_start", "WinMain", "DllMain", "entry", "start"]
            for name in common_entries:
                for func in func_manager.getFunctions(True):
                    if func.getName() == name:
                        entry = func.getEntryPoint()
                        # Avoid duplicates
                        if not any(ep["address"] == str(entry) for ep in entry_points):
                            entry_points.append(
                                {
                                    "name": name,
                                    "address": str(entry),
                                    "offset": entry.getOffset() if entry else 0,
                                    "is_function": True,
                                    "type": "named_entry",
                                }
                            )
                        break

            logger.info(f"Found {len(entry_points)} entry points")
            return entry_points

        except Exception as e:
            logger.error(f"Error getting entry points: {e}")
            return []

    def get_function_variables(self, target: str) -> dict[str, Any] | None:
        """Get all variables (parameters and locals) for a function."""
        func = self._find_function(target)
        if not func:
            return None

        try:
            parameters = []
            for param in func.getParameters():
                parameters.append(
                    {
                        "name": param.getName(),
                        "ordinal": param.getOrdinal(),
                        "type": str(param.getDataType()),
                        "storage": str(param.getVariableStorage()),
                        "size": param.getLength(),
                    }
                )

            local_vars = []
            for var in func.getLocalVariables():
                local_vars.append(
                    {
                        "name": var.getName(),
                        "type": str(var.getDataType()),
                        "storage": str(var.getVariableStorage()),
                        "size": var.getLength(),
                        "first_use_offset": var.getFirstUseOffset(),
                    }
                )

            return {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "parameter_count": len(parameters),
                "local_count": len(local_vars),
                "parameters": parameters,
                "locals": local_vars,
            }

        except Exception as e:
            logger.error(f"Error getting function variables: {e}")
            return None

    def get_function_hash(self, target: str) -> dict[str, Any] | None:
        """Get SHA-256 hash of normalized function opcodes.

        This hash can be used to match identical functions across different
        binary versions, even if they're at different addresses.
        """
        import hashlib

        func = self._find_function(target)
        if not func:
            return None

        try:
            listing = self._program.getListing()
            body = func.getBody()
            if not body:
                return None

            # Collect normalized opcodes
            opcodes = []
            instruction_count = 0

            for instr in listing.getInstructions(body, True):
                instruction_count += 1
                mnemonic = instr.getMnemonicString()
                opcodes.append(mnemonic)

                # Add operand types (normalized)
                for i in range(instr.getNumOperands()):
                    op_type = instr.getOperandType(i)
                    # Normalize: just use operand type, not actual values
                    opcodes.append(f"OP{op_type}")

            # Create hash from normalized opcodes
            opcode_str = "|".join(opcodes)
            hash_value = hashlib.sha256(opcode_str.encode()).hexdigest()

            return {
                "name": func.getName(),
                "address": str(func.getEntryPoint()),
                "hash": hash_value,
                "instruction_count": instruction_count,
                "has_custom_name": not func.getName().startswith("FUN_"),
            }

        except Exception as e:
            logger.error(f"Error getting function hash: {e}")
            return None

    def search_byte_patterns(
        self, pattern_hex: str, max_results: int = 100
    ) -> list[dict[str, Any]]:
        """Search for byte patterns in memory.

        Args:
            pattern_hex: Hex string pattern (e.g., "4889e5" or "48 89 e5")
            max_results: Maximum number of results to return.

        Returns:
            List of matches with address and context.
        """
        if not self._program:
            return []

        try:
            # Clean pattern
            pattern_hex = pattern_hex.replace(" ", "").lower()
            pattern_bytes = bytes.fromhex(pattern_hex)

            memory = self._program.getMemory()
            results = []

            # Search in each memory block
            for block in memory.getBlocks():
                if not block.isInitialized():
                    continue

                start = block.getStart()

                # Read block data
                size = min(block.getSize(), 10 * 1024 * 1024)  # Max 10MB per block
                data = bytearray(size)
                try:
                    memory.getBytes(start, data)
                except Exception:
                    continue

                # Search for pattern
                data_bytes = bytes(data)
                offset = 0
                while len(results) < max_results:
                    idx = data_bytes.find(pattern_bytes, offset)
                    if idx == -1:
                        break

                    match_addr = start.add(idx)
                    func_manager = self._program.getFunctionManager()
                    containing_func = func_manager.getFunctionContaining(match_addr)

                    # Get context bytes
                    context_start = max(0, idx - 8)
                    context_end = min(len(data_bytes), idx + len(pattern_bytes) + 8)
                    context = data_bytes[context_start:context_end].hex()

                    results.append(
                        {
                            "address": str(match_addr),
                            "offset": match_addr.getOffset(),
                            "section": block.getName(),
                            "function": containing_func.getName() if containing_func else None,
                            "context_hex": context,
                        }
                    )

                    offset = idx + 1

            logger.info(f"Found {len(results)} matches for pattern {pattern_hex[:16]}...")
            return results

        except Exception as e:
            logger.error(f"Error searching byte patterns: {e}")
            return []

    def list_globals(self, limit: int = 500) -> list[dict[str, Any]]:
        """Get global variables (defined data with labels)."""
        if not self._program:
            return []

        globals_list = []
        try:
            listing = self._program.getListing()
            symbol_table = self._program.getSymbolTable()

            for data in listing.getDefinedData(True):
                if len(globals_list) >= limit:
                    break

                addr = data.getAddress()
                # Skip if in function body
                func_manager = self._program.getFunctionManager()
                if func_manager.getFunctionContaining(addr):
                    continue

                # Get symbol/label
                symbols = symbol_table.getSymbols(addr)
                label = None
                for sym in symbols:
                    if not sym.isDynamic():
                        label = sym.getName()
                        break

                data_type = data.getDataType()
                globals_list.append(
                    {
                        "address": str(addr),
                        "offset": addr.getOffset(),
                        "label": label or f"DAT_{addr}",
                        "type": str(data_type) if data_type else "undefined",
                        "size": data.getLength(),
                        "value": self._safe_data_value(data),
                    }
                )

            logger.info(f"Found {len(globals_list)} global variables")
            return globals_list

        except Exception as e:
            logger.error(f"Error listing globals: {e}")
            return []

    def _safe_data_value(self, data) -> str:
        """Safely get data value as string."""
        try:
            value = data.getValue()
            if value is None:
                return ""
            # Truncate long values
            str_val = str(value)
            return str_val[:100] if len(str_val) > 100 else str_val
        except Exception:
            return ""

    def run_script(
        self, script_code: str, script_args: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Execute a Python script in the Ghidra context.

        The script has access to:
        - `program`: The current program
        - `flat_api`: Ghidra FlatProgramAPI
        - `listing`: Program listing
        - `func_manager`: Function manager
        - `symbol_table`: Symbol table
        - `memory`: Memory object
        - `args`: Script arguments (dict)
        - `results`: Dict to store results (script should populate this)

        Args:
            script_code: Python code to execute.
            script_args: Optional arguments passed to the script.

        Returns:
            Dict with 'success', 'results', and optionally 'error'.

        Example script:
            ```python
            # Count functions by prefix
            count = 0
            for func in func_manager.getFunctions(True):
                if func.getName().startswith(args.get('prefix', 'FUN_')):
                    count += 1
            results['count'] = count
            results['prefix'] = args.get('prefix', 'FUN_')
            ```
        """
        if not self._program:
            return {"success": False, "error": "Program not opened"}

        try:
            # Build execution context
            exec_globals = {
                "program": self._program,
                "flat_api": self._flat_api,
                "listing": self._program.getListing(),
                "func_manager": self._program.getFunctionManager(),
                "symbol_table": self._program.getSymbolTable(),
                "memory": self._program.getMemory(),
                "args": script_args or {},
                "results": {},
                # Utility functions
                "get_function": self._find_function,
                "decompile": self.decompile_function,
                "get_xrefs": self.get_function_xrefs,
            }

            # Execute script
            exec(script_code, exec_globals)

            return {
                "success": True,
                "results": exec_globals["results"],
            }

        except Exception as e:
            logger.error(f"Script execution error: {e}")
            return {
                "success": False,
                "error": str(e),
                "results": {},
            }

    def clear_flow_overrides(self, target: str | None = None) -> dict[str, Any]:
        """Clear incorrect flow overrides that prevent proper control flow analysis.

        This is similar to ghidra-mcp's ClearCallReturnOverrides script.
        Clears CALL_RETURN overrides that cause incomplete decompilation.

        Args:
            target: Optional function name/address. If None, clears all.

        Returns:
            Dict with statistics about cleared overrides.
        """
        if not self._program:
            return {"success": False, "error": "Program not opened"}

        try:
            from ghidra.program.model.listing import FlowOverride

            listing = self._program.getListing()
            stats = {
                "calls_checked": 0,
                "overrides_found": 0,
                "overrides_cleared": 0,
                "affected_functions": [],
            }

            # Determine scope
            if target:
                func = self._find_function(target)
                if not func:
                    return {"success": False, "error": f"Function not found: {target}"}
                instructions = listing.getInstructions(func.getBody(), True)
            else:
                instructions = listing.getInstructions(True)

            func_manager = self._program.getFunctionManager()

            for instr in instructions:
                # Check if CALL instruction
                if instr.getFlowType().isCall():
                    stats["calls_checked"] += 1

                    # Check for CALL_RETURN override
                    flow_override = instr.getFlowOverride()
                    if flow_override == FlowOverride.CALL_RETURN:
                        stats["overrides_found"] += 1

                        # Get containing function
                        containing_func = func_manager.getFunctionContaining(instr.getAddress())
                        func_name = containing_func.getName() if containing_func else "unknown"

                        # Clear the override
                        instr.setFlowOverride(FlowOverride.NONE)
                        stats["overrides_cleared"] += 1

                        if func_name not in stats["affected_functions"]:
                            stats["affected_functions"].append(func_name)

                        logger.info(f"Cleared CALL_RETURN at {instr.getAddress()} in {func_name}")

            stats["success"] = True
            logger.info(f"Cleared {stats['overrides_cleared']} flow overrides")
            return stats

        except Exception as e:
            logger.error(f"Error clearing flow overrides: {e}")
            return {"success": False, "error": str(e)}

    def find_orphan_code(self, min_size: int = 10) -> list[dict[str, Any]]:
        """Find potential orphan code regions (code not in any function).

        This helps discover undiscovered functions in gaps between known code.

        Args:
            min_size: Minimum number of instructions to consider.

        Returns:
            List of orphan code regions with address and size.
        """
        if not self._program:
            return []

        try:
            listing = self._program.getListing()
            func_manager = self._program.getFunctionManager()
            orphans = []

            current_orphan = None
            instruction_count = 0

            for instr in listing.getInstructions(True):
                addr = instr.getAddress()
                containing_func = func_manager.getFunctionContaining(addr)

                if containing_func is None:
                    # This instruction is not in any function
                    if current_orphan is None:
                        current_orphan = {
                            "start_address": str(addr),
                            "start_offset": addr.getOffset(),
                        }
                        instruction_count = 1
                    else:
                        instruction_count += 1
                else:
                    # End of orphan region
                    if current_orphan is not None and instruction_count >= min_size:
                        current_orphan["instruction_count"] = instruction_count
                        current_orphan["end_address"] = str(instr.getAddress())

                        # Try to identify what this might be
                        first_instr = listing.getInstructionAt(
                            self._program.getAddressFactory().getAddress(
                                current_orphan["start_address"]
                            )
                        )
                        if first_instr:
                            current_orphan["first_mnemonic"] = first_instr.getMnemonicString()

                        orphans.append(current_orphan)

                    current_orphan = None
                    instruction_count = 0

            # Handle last orphan region
            if current_orphan is not None and instruction_count >= min_size:
                current_orphan["instruction_count"] = instruction_count
                orphans.append(current_orphan)

            logger.info(f"Found {len(orphans)} orphan code regions")
            return orphans

        except Exception as e:
            logger.error(f"Error finding orphan code: {e}")
            return []

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
