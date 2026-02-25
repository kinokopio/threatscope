"""Process monitor for dynamic analysis using psutil."""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)

try:
    import psutil
except ImportError:
    psutil = None
    logger.warning("psutil not available, process monitoring disabled")


@dataclass
class MonitorResult:
    """Result of process monitoring."""

    success: bool
    process_ids: list[tuple[int, str]] = field(default_factory=list)
    network_connections: list[dict[str, Any]] = field(default_factory=list)
    open_files: list[dict[str, Any]] = field(default_factory=list)
    syscalls: dict[str, int] = field(default_factory=dict)
    error: str | None = None
    duration_seconds: float = 0


@dataclass
class ConnectionInfo:
    """Network connection information."""

    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    status: str
    local_port: int = 0


class ProcessMonitor:
    """Monitors process behavior including network, files, and children.

    This is a simplified version that uses psutil for cross-platform
    process monitoring without requiring Frida.
    """

    def __init__(self, monitor_duration: int = 30):
        """Initialize monitor.

        Args:
            monitor_duration: How long to monitor in seconds.
        """
        self.monitor_duration = monitor_duration
        self._running = False
        self._result = MonitorResult(success=False)

    async def monitor_pid(
        self,
        pid: int,
        on_event: Callable[[str, Any], None] | None = None,
    ) -> MonitorResult:
        """Monitor a process by PID.

        Args:
            pid: Process ID to monitor.
            on_event: Optional callback for events.

        Returns:
            MonitorResult with collected data.
        """
        if psutil is None:
            return MonitorResult(success=False, error="psutil not available")

        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return MonitorResult(success=False, error=f"Process {pid} not found")
        except psutil.AccessDenied:
            return MonitorResult(success=False, error=f"Access denied to process {pid}")

        self._running = True
        self._result = MonitorResult(success=True)
        start_time = asyncio.get_event_loop().time()

        # Track processes
        tracked_pids = {pid}
        self._result.process_ids.append((pid, proc.name()))

        try:
            while self._running:
                elapsed = asyncio.get_event_loop().time() - start_time
                if elapsed >= self.monitor_duration:
                    break

                # Check if main process still alive
                if not psutil.pid_exists(pid):
                    break

                # Gather child processes
                await self._gather_children(proc, tracked_pids, on_event)

                # Gather network connections
                await self._gather_network(tracked_pids, on_event)

                # Gather open files
                await self._gather_files(tracked_pids, on_event)

                await asyncio.sleep(0.5)

            self._result.duration_seconds = asyncio.get_event_loop().time() - start_time
            return self._result

        except Exception as e:
            self._result.error = str(e)
            self._result.success = False
            return self._result

        finally:
            self._running = False

    async def _gather_children(
        self,
        proc: "psutil.Process",
        tracked_pids: set[int],
        on_event: Callable | None,
    ) -> None:
        """Gather child processes."""
        try:
            for child in proc.children(recursive=True):
                if child.pid not in tracked_pids:
                    tracked_pids.add(child.pid)
                    entry = (child.pid, child.name())
                    if entry not in self._result.process_ids:
                        self._result.process_ids.append(entry)
                        if on_event:
                            on_event("child_process", {"pid": child.pid, "name": child.name()})
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    async def _gather_network(
        self,
        tracked_pids: set[int],
        on_event: Callable | None,
    ) -> None:
        """Gather network connections."""
        for pid in list(tracked_pids):
            try:
                proc = psutil.Process(pid)
                for conn in proc.connections():
                    if conn.raddr:
                        conn_info = {
                            "pid": pid,
                            "process_name": proc.name(),
                            "remote_ip": conn.raddr.ip,
                            "remote_port": conn.raddr.port,
                            "local_port": conn.laddr.port if conn.laddr else 0,
                            "status": conn.status,
                        }
                        # Deduplicate
                        key = f"{pid}:{conn.raddr.ip}:{conn.raddr.port}"
                        if not any(c.get("_key") == key for c in self._result.network_connections):
                            conn_info["_key"] = key
                            self._result.network_connections.append(conn_info)
                            if on_event:
                                on_event("network_connection", conn_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    async def _gather_files(
        self,
        tracked_pids: set[int],
        on_event: Callable | None,
    ) -> None:
        """Gather open files."""
        for pid in list(tracked_pids):
            try:
                proc = psutil.Process(pid)
                for f in proc.open_files():
                    file_info = {
                        "pid": pid,
                        "path": f.path,
                        "mode": f.mode if hasattr(f, "mode") else "unknown",
                    }
                    # Deduplicate
                    key = f"{pid}:{f.path}"
                    if not any(c.get("_key") == key for c in self._result.open_files):
                        file_info["_key"] = key
                        self._result.open_files.append(file_info)
                        if on_event:
                            on_event("open_file", file_info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False


class DynamicAnalyzer:
    """Combined dynamic analyzer using emulation and monitoring."""

    def __init__(
        self,
        emulation_timeout: int = 180,
        monitor_duration: int = 30,
    ):
        """Initialize dynamic analyzer.

        Args:
            emulation_timeout: Timeout for binary emulation.
            monitor_duration: Duration for process monitoring.
        """
        from tools.dynamic.emulator import BinaryEmulator

        self.emulator = BinaryEmulator(timeout=emulation_timeout)
        self.monitor = ProcessMonitor(monitor_duration=monitor_duration)

    def emulate(self, binary_path: str, arch: str) -> dict[str, Any]:
        """Emulate binary execution.

        Args:
            binary_path: Path to binary.
            arch: Target architecture.

        Returns:
            Emulation results.
        """
        result = self.emulator.emulate(binary_path, arch)
        return {
            "success": result.success,
            "method": result.method,
            "syscalls": result.syscalls,
            "syscall_count": len(result.syscalls),
            "error": result.error,
        }

    async def monitor_process(
        self,
        pid: int,
        on_event: Callable | None = None,
    ) -> dict[str, Any]:
        """Monitor a running process.

        Args:
            pid: Process ID.
            on_event: Event callback.

        Returns:
            Monitoring results.
        """
        result = await self.monitor.monitor_pid(pid, on_event)
        return {
            "success": result.success,
            "process_ids": result.process_ids,
            "network_connections": [
                {k: v for k, v in c.items() if not k.startswith("_")}
                for c in result.network_connections
            ],
            "open_files": [
                {k: v for k, v in f.items() if not k.startswith("_")} for f in result.open_files
            ],
            "duration_seconds": result.duration_seconds,
            "error": result.error,
        }

    def analyze(self, binary_path: str, arch: str) -> dict[str, Any]:
        """Run full dynamic analysis (emulation only for now).

        Args:
            binary_path: Path to binary.
            arch: Target architecture.

        Returns:
            Combined analysis results.
        """
        return {
            "emulation": self.emulate(binary_path, arch),
            "monitoring": None,  # Would require running the binary
        }
