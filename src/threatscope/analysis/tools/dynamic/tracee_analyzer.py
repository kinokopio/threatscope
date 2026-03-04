"""Tracee-based dynamic analysis for malware sandbox.

Uses Aqua Tracee (eBPF) for comprehensive runtime security monitoring.
Reference: https://aquasecurity.github.io/tracee/v0.24/docs/overview/
"""

import json
import logging
import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class TraceeConfig:
    """Configuration for Tracee analyzer."""

    timeout: int = 30
    tracee_image: str = "aquasec/tracee:latest"
    sandbox_image: str = "ubuntu:22.04"
    output_dir: str = "/tmp/tracee-output"
    enable_network_capture: bool = True
    enable_file_capture: bool = True


@dataclass
class DynamicAnalysisResult:
    """Result of dynamic analysis."""

    success: bool
    duration_seconds: float = 0.0
    # 优化后的摘要数据（给前端和AI）
    process_tree: list[dict[str, Any]] = field(default_factory=list)
    network_summary: dict[str, Any] = field(default_factory=dict)
    security_events: list[dict[str, Any]] = field(default_factory=list)
    syscall_summary: dict[str, Any] = field(default_factory=dict)
    file_activity: dict[str, Any] = field(default_factory=dict)
    # 原始数据（调试用）
    raw_events_count: int = 0
    error: str | None = None
    method: str = "tracee"
    event_types: list[str] = field(default_factory=list)


class TraceeAnalyzer:
    """Dynamic analysis using Aqua Tracee eBPF.

    Architecture:
    1. Create isolated sandbox container to run malware sample
    2. Start Tracee container to monitor the sandbox
    3. Execute sample in sandbox
    4. Collect and parse Tracee events
    5. Cleanup all containers

    Tracee automatically detects 30+ security events including:
    - fileless_execution
    - dropped_executable
    - hidden_file_created
    - ld_preload injection
    - anti_debugging
    - stdio_over_socket (reverse shell)
    - And more...
    """

    # Security events we care about for malware analysis
    SECURITY_EVENTS = {
        "fileless_execution",
        "dropped_executable",
        "hidden_file_created",
        "dynamic_code_loading",
        "ld_preload",
        "anti_debugging",
        "stdio_over_socket",
        "ptrace_code_injection",
        "kernel_module_loading",
        "scheduled_task_modification",
        "proc_mem_code_injection",
        "process_vm_write_code_injection",
        "illegitimate_shell",
        "docker_abuse",
        "disk_mount",
        "security_socket_bind",
        "security_socket_connect",
        "security_socket_create",
        "security_bprm_check",
        "security_file_mprotect",
        "magic_write",
        "mem_prot_alert",
    }

    # Network events
    NETWORK_EVENTS = {
        "net_packet_dns",
        "net_packet_dns_request",
        "net_packet_dns_response",
        "net_packet_http",
        "net_packet_http_request",
        "net_packet_http_response",
        "net_tcp_connect",
        "net_flow_tcp_begin",
        "net_flow_tcp_end",
    }

    # Process lifecycle events
    PROCESS_EVENTS = {
        "sched_process_exec",
        "sched_process_fork",
        "sched_process_exit",
    }

    # File events
    FILE_EVENTS = {
        "security_file_open",
        "vfs_write",
        "vfs_read",
        "security_inode_unlink",
        "security_inode_rename",
    }

    def __init__(self, config: TraceeConfig | None = None):
        """Initialize Tracee analyzer.

        Args:
            config: Tracee configuration. Uses defaults if not provided.
        """
        self.config = config or TraceeConfig()
        self._docker_available = shutil.which("docker") is not None
        self._tracee_process: subprocess.Popen | None = None

    def analyze(self, binary_path: str, arch: str = "x86_64") -> DynamicAnalysisResult:
        """Run dynamic analysis on a binary using Tracee.

        Args:
            binary_path: Path to the binary to analyze.
            arch: Target architecture (only x86_64 supported with Tracee).

        Returns:
            DynamicAnalysisResult with security events, network activity, etc.
        """
        if not self._docker_available:
            return DynamicAnalysisResult(
                success=False,
                error="Docker is required for Tracee analysis",
            )

        # Tracee uses eBPF which requires native architecture
        if arch.lower() not in ("x86_64", "amd64"):
            return DynamicAnalysisResult(
                success=False,
                error=f"Tracee only supports native x86_64 architecture, got: {arch}",
            )

        if not os.path.exists(binary_path):
            return DynamicAnalysisResult(
                success=False,
                error=f"Binary not found: {binary_path}",
            )

        start_time = time.time()
        sandbox_name = f"tracee-sandbox-{uuid.uuid4().hex[:8]}"
        tracee_name = f"tracee-monitor-{uuid.uuid4().hex[:8]}"
        network_name = f"tracee-net-{uuid.uuid4().hex[:8]}"
        output_file = None

        try:
            output_dir = Path(self.config.output_dir) / sandbox_name
            output_dir.mkdir(parents=True, exist_ok=True)
            output_file = output_dir / "events.json"

            self._create_isolated_network(network_name)

            logger.info(f"Creating sandbox container: {sandbox_name}")
            sandbox_id = self._create_sandbox(sandbox_name, binary_path, network_name)
            if not sandbox_id:
                return DynamicAnalysisResult(
                    success=False,
                    error="Failed to create sandbox container",
                )

            # Step 2: Start Tracee to monitor the sandbox (use container ID)
            logger.info(f"Starting Tracee monitor: {tracee_name}")
            tracee_started = self._start_tracee(tracee_name, sandbox_id, str(output_file))
            if not tracee_started:
                return DynamicAnalysisResult(
                    success=False,
                    error="Failed to start Tracee monitor",
                )

            logger.info("Waiting for Tracee to initialize eBPF probes...")
            time.sleep(5)

            logger.info("Executing sample in sandbox...")
            exec_success = self._execute_sample(sandbox_name, self.config.timeout)

            logger.info("Waiting for events to be collected...")
            time.sleep(3)

            logger.info("Stopping Tracee and collecting events...")
            self._stop_tracee()
            events = self._parse_events(output_file)
            logger.info(f"Parsed {len(events)} events from Tracee output")
            duration = time.time() - start_time

            return self._build_result(events, duration, exec_success)

        except Exception as e:
            logger.exception(f"Dynamic analysis failed: {e}")
            return DynamicAnalysisResult(
                success=False,
                error=str(e),
                duration_seconds=time.time() - start_time,
            )

        finally:
            # Cleanup
            self._cleanup(sandbox_name, tracee_name, network_name)
            if output_file and output_file.parent.exists():
                try:
                    shutil.rmtree(output_file.parent)
                except Exception:
                    pass

    def _create_isolated_network(self, network_name: str) -> bool:
        try:
            subprocess.run(
                [
                    "docker",
                    "network",
                    "create",
                    "--internal",  # No external access
                    "--driver",
                    "bridge",
                    network_name,
                ],
                capture_output=True,
                timeout=30,
            )
            return True
        except Exception as e:
            logger.warning(f"Failed to create network: {e}")
            return False

    def _create_sandbox(self, name: str, binary_path: str, network_name: str) -> str | None:
        try:
            result = subprocess.run(
                [
                    "docker",
                    "create",
                    "--name",
                    name,
                    "--network",
                    network_name,
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges:true",
                    "--pids-limit",
                    "128",
                    "--memory",
                    "512m",
                    "--cpus",
                    "0.5",
                    "-w",
                    "/sandbox",
                    self.config.sandbox_image,
                    "sleep",
                    "infinity",
                ],
                capture_output=True,
                timeout=30,
            )

            if result.returncode != 0:
                logger.error(f"Failed to create sandbox: {result.stderr.decode()}")
                return None

            container_id = result.stdout.decode().strip()

            # Copy binary into container
            binary_name = os.path.basename(binary_path)
            subprocess.run(
                ["docker", "cp", binary_path, f"{name}:/sandbox/{binary_name}"],
                capture_output=True,
                timeout=30,
            )

            # Start the container
            subprocess.run(
                ["docker", "start", name],
                capture_output=True,
                timeout=30,
            )

            # Make binary executable
            subprocess.run(
                ["docker", "exec", name, "chmod", "+x", f"/sandbox/{binary_name}"],
                capture_output=True,
                timeout=10,
            )

            return container_id

        except Exception as e:
            logger.error(f"Failed to create sandbox: {e}")
            return None

    def _start_tracee(self, name: str, sandbox_container_id: str, output_file: str) -> bool:
        """Start Tracee to monitor the sandbox container.

        Args:
            name: Tracee container name.
            sandbox_container_id: Container ID of the sandbox to monitor.
            output_file: Path to write events JSON.

        Returns:
            True if Tracee started successfully.
        """
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            cmd = [
                "docker",
                "run",
                "--rm",
                "--name",
                name,
                "--pid=host",
                "--cgroupns=host",
                "--privileged",
                "-v",
                "/etc/os-release:/etc/os-release-host:ro",
                "-v",
                "/var/run:/var/run:ro",
                self.config.tracee_image,
                "--scope",
                f"container={sandbox_container_id}",
                "--events",
                ",".join(
                    [
                        "sched_process_exec",
                        "sched_process_fork",
                        "sched_process_exit",
                        "dynamic_code_loading",
                        "fileless_execution",
                        "dropped_executable",
                        "hidden_file_created",
                        "ld_preload",
                        "stdio_over_socket",
                        "anti_debugging",
                        "net_packet_dns",
                        "net_packet_dns_request",
                        "net_packet_dns_response",
                        "net_packet_http",
                        "net_packet_http_request",
                        "net_tcp_connect",
                        "security_socket_bind",
                        "security_socket_connect",
                        "security_socket_create",
                        "security_file_open",
                        "vfs_write",
                        "vfs_read",
                        "setuid",
                        "setgid",
                        "execve",
                        "openat",
                        "close",
                        "read",
                        "write",
                        "mmap",
                        "mprotect",
                        "clone",
                        "fork",
                    ]
                ),
                "--output",
                "json",
            ]

            logger.info(f"Starting Tracee: {' '.join(cmd)}")
            logger.info(f"Monitoring container ID: {sandbox_container_id}")

            with open(output_path, "w") as outfile:
                self._tracee_process = subprocess.Popen(
                    cmd,
                    stdout=outfile,
                    stderr=subprocess.PIPE,
                )

            time.sleep(3)

            if self._tracee_process.poll() is not None:
                stderr = (
                    self._tracee_process.stderr.read().decode()
                    if self._tracee_process.stderr
                    else ""
                )
                logger.error(f"Tracee exited early: {stderr}")
                return False

            if self._tracee_process.stderr:
                import select

                if select.select([self._tracee_process.stderr], [], [], 0)[0]:
                    stderr_preview = self._tracee_process.stderr.read(1024).decode()
                    if stderr_preview:
                        logger.warning(f"Tracee stderr: {stderr_preview}")

            logger.info("Tracee started successfully, waiting for events...")
            return True

        except Exception as e:
            logger.error(f"Failed to start Tracee: {e}")
            return False

    def _execute_sample(self, sandbox_name: str, timeout: int) -> bool:
        """Execute the malware sample in the sandbox.

        Args:
            sandbox_name: Sandbox container name.
            timeout: Execution timeout in seconds.

        Returns:
            True if execution completed (even if sample crashed).
        """
        try:
            # Find the binary in /sandbox
            result = subprocess.run(
                ["docker", "exec", sandbox_name, "ls", "/sandbox"],
                capture_output=True,
                timeout=10,
            )

            if result.returncode != 0:
                return False

            files = result.stdout.decode().strip().split("\n")
            binary_name = files[0] if files else None

            if not binary_name:
                logger.error("No binary found in sandbox")
                return False

            # Execute with timeout
            subprocess.run(
                [
                    "docker",
                    "exec",
                    sandbox_name,
                    "timeout",
                    "--signal=KILL",
                    str(timeout),
                    f"/sandbox/{binary_name}",
                ],
                capture_output=True,
                timeout=timeout + 10,
            )

            return True

        except subprocess.TimeoutExpired:
            logger.warning(f"Sample execution timed out after {timeout}s")
            return True
        except Exception as e:
            logger.error(f"Failed to execute sample: {e}")
            return False

    def _stop_tracee(self) -> None:
        if hasattr(self, "_tracee_process") and self._tracee_process:
            try:
                self._tracee_process.terminate()
                self._tracee_process.wait(timeout=10)
            except Exception:
                try:
                    self._tracee_process.kill()
                except Exception:
                    pass

    def _stop_container(self, name: str) -> None:
        try:
            subprocess.run(
                ["docker", "stop", "-t", "2", name],
                capture_output=True,
                timeout=10,
            )
        except Exception:
            pass

    def _cleanup(self, sandbox_name: str, tracee_name: str, network_name: str = "") -> None:
        self._stop_tracee()
        for name in [sandbox_name, tracee_name]:
            try:
                subprocess.run(
                    ["docker", "rm", "-f", name],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
        if network_name:
            try:
                subprocess.run(
                    ["docker", "network", "rm", network_name],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass

    def _parse_events(self, output_file: Path) -> list[dict[str, Any]]:
        events = []

        if not output_file.exists():
            logger.warning(f"Events file not found: {output_file}")
            return events

        try:
            file_size = output_file.stat().st_size
            logger.info(f"Events file size: {file_size} bytes")

            with open(output_file, "r") as f:
                content = f.read()
                logger.info(f"Events file content preview: {content[:500]}")

            with open(output_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            event = json.loads(line)
                            events.append(event)
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse line: {line[:100]}... Error: {e}")
                            continue
        except Exception as e:
            logger.error(f"Failed to parse events: {e}")

        return events

    def _build_result(
        self, events: list[dict[str, Any]], duration: float, exec_success: bool
    ) -> DynamicAnalysisResult:
        """Build structured result from raw Tracee events."""
        security_events = []
        network_info = {"dns_queries": [], "connections": [], "http_requests": []}
        processes = []
        file_activity = {"created": [], "modified": [], "deleted": [], "executed": []}
        syscalls = []

        seen_processes = set()
        seen_files = set()
        event_types_seen = set()

        for event in events:
            event_name = event.get("eventName", "")
            process_name = event.get("processName", "")
            event_types_seen.add(event_name)
            logger.debug(
                f"Event: {event_name} from process: {process_name} (pid={event.get('processId')})"
            )

        for event in events:
            event_name = event.get("eventName", "")
            process_name = event.get("processName", "")

            if process_name in ("qemu-x86_64-sta", "qemu-aarch64-sta", "qemu-arm-sta"):
                continue

            # Security events
            if event_name in self.SECURITY_EVENTS:
                security_events.append(
                    {
                        "event": event_name,
                        "timestamp": event.get("timestamp"),
                        "process": process_name,
                        "pid": event.get("processId"),
                        "description": self._get_event_description(event),
                        "severity": self._get_event_severity(event_name),
                        "args": event.get("args", []),
                    }
                )

            # Network events
            elif event_name in self.NETWORK_EVENTS:
                self._process_network_event(event, network_info)

            # Process events
            elif event_name in self.PROCESS_EVENTS:
                proc_key = (event.get("processId"), event.get("processName"))
                if proc_key not in seen_processes:
                    seen_processes.add(proc_key)
                    processes.append(
                        {
                            "pid": event.get("processId"),
                            "ppid": event.get("parentProcessId"),
                            "name": event.get("processName"),
                            "cmdline": self._extract_cmdline(event),
                            "timestamp": event.get("timestamp"),
                        }
                    )

            # File events
            elif event_name in self.FILE_EVENTS:
                self._process_file_event(event, file_activity, seen_files)

            # Collect interesting events as syscalls
            if event_name in (
                "setuid",
                "setgid",
                "setpgid",
                "setsid",
                "execve",
                "open",
                "connect",
                "socket",
                "bind",
                "fork",
                "clone",
                "ptrace",
                "mmap",
                "mprotect",
            ) or event_name.startswith("sys_"):
                if len(syscalls) < 1000:
                    syscalls.append(
                        {
                            "name": event_name,
                            "pid": event.get("processId"),
                            "timestamp": event.get("timestamp"),
                            "args": event.get("args", []),
                            "returnValue": event.get("returnValue"),
                        }
                    )

        # 构建进程树
        process_tree = self._build_process_tree(processes)

        # 构建网络摘要（去重）
        network_summary = self._build_network_summary(network_info)

        # 构建 syscall 摘要（按类型分组统计）
        syscall_summary = self._build_syscall_summary(syscalls)

        # 去重 security_events
        unique_security_events = self._dedupe_security_events(security_events)

        return DynamicAnalysisResult(
            success=exec_success and len(events) > 0,
            duration_seconds=duration,
            process_tree=process_tree,
            network_summary=network_summary,
            security_events=unique_security_events,
            syscall_summary=syscall_summary,
            file_activity=file_activity,
            raw_events_count=len(events),
            method="tracee",
            event_types=list(event_types_seen),
        )

    def _get_event_description(self, event: dict[str, Any]) -> str:
        """Get human-readable description for an event."""
        metadata = event.get("metadata", {})
        if isinstance(metadata, dict):
            return metadata.get("Description", "")

        descriptions = {
            "fileless_execution": "Process executed from memory without file on disk",
            "dropped_executable": "Executable file was dropped during runtime",
            "hidden_file_created": "Hidden file was created",
            "dynamic_code_loading": "Code was dynamically loaded into process",
            "ld_preload": "LD_PRELOAD environment variable injection detected",
            "anti_debugging": "Anti-debugging technique detected",
            "stdio_over_socket": "Standard I/O redirected over socket (possible reverse shell)",
            "ptrace_code_injection": "Code injection via ptrace detected",
        }
        return descriptions.get(event.get("eventName", ""), "")

    def _get_event_severity(self, event_name: str) -> str:
        """Get severity level for a security event."""
        high_severity = {
            "fileless_execution",
            "ptrace_code_injection",
            "proc_mem_code_injection",
            "process_vm_write_code_injection",
            "kernel_module_loading",
            "syscall_table_hooking",
        }
        medium_severity = {
            "dropped_executable",
            "hidden_file_created",
            "ld_preload",
            "stdio_over_socket",
            "anti_debugging",
            "scheduled_task_modification",
        }

        if event_name in high_severity:
            return "high"
        elif event_name in medium_severity:
            return "medium"
        return "low"

    def _process_network_event(self, event: dict[str, Any], network_info: dict[str, list]) -> None:
        event_name = event.get("eventName", "")
        args = {arg.get("name"): arg.get("value") for arg in event.get("args", [])}

        if "dns" in event_name.lower():
            dns_responses = args.get("dns_response", [])
            if isinstance(dns_responses, list):
                for resp in dns_responses:
                    if isinstance(resp, dict):
                        query_data = resp.get("query_data", {})
                        query = query_data.get("query", "") if isinstance(query_data, dict) else ""
                        answers = resp.get("dns_answer", [])
                        answer_str = (
                            ", ".join(a.get("answer", "") for a in answers if isinstance(a, dict))
                            if isinstance(answers, list)
                            else ""
                        )
                        if query:
                            network_info["dns_queries"].append(
                                {
                                    "domain": query,
                                    "response": answer_str,
                                    "timestamp": event.get("timestamp"),
                                }
                            )

        elif event_name in ("net_tcp_connect", "net_flow_tcp_begin"):
            network_info["connections"].append(
                {
                    "remote_ip": args.get("dst") or args.get("remote_addr"),
                    "remote_port": args.get("dst_port") or args.get("remote_port"),
                    "protocol": "tcp",
                    "timestamp": event.get("timestamp"),
                }
            )

        elif "http" in event_name.lower():
            network_info["http_requests"].append(
                {
                    "method": args.get("method"),
                    "host": args.get("host"),
                    "uri": args.get("uri"),
                    "timestamp": event.get("timestamp"),
                }
            )

    def _process_file_event(
        self, event: dict[str, Any], file_activity: dict[str, list], seen: set
    ) -> None:
        """Process file-related events."""
        args = {arg.get("name"): arg.get("value") for arg in event.get("args", [])}
        pathname = args.get("pathname") or args.get("path")

        if not pathname or pathname in seen:
            return

        seen.add(pathname)
        event_name = event.get("eventName", "")

        if event_name == "security_inode_unlink":
            file_activity["deleted"].append(pathname)
        elif event_name == "vfs_write":
            file_activity["modified"].append(pathname)
        elif event_name == "security_file_open":
            flags = args.get("flags", 0)
            if isinstance(flags, int) and flags & 0x40:  # O_CREAT
                file_activity["created"].append(pathname)

    def _extract_cmdline(self, event: dict[str, Any]) -> str:
        """Extract command line from process event."""
        args = event.get("args", [])
        for arg in args:
            if arg.get("name") in ("cmdline", "argv"):
                value = arg.get("value")
                if isinstance(value, list):
                    return " ".join(str(v) for v in value)
                return str(value) if value else ""
        return ""

    def _build_process_tree(self, processes: list[dict]) -> list[dict]:
        """Build hierarchical process tree from flat process list."""
        if not processes:
            return []

        # Filter out noise processes (container init, our ls command)
        noise_names = {"runc:[2:INIT]", "runc:[1:CHILD]", "ls", "sleep"}
        noise_cmdlines = {"ls /sandbox", "sleep infinity"}

        filtered = []
        for proc in processes:
            name = proc.get("name", "")
            cmdline = proc.get("cmdline", "")
            if name in noise_names or cmdline in noise_cmdlines:
                continue
            filtered.append(proc)

        if not filtered:
            return []

        # Create lookup by pid
        by_pid = {p["pid"]: p for p in filtered}

        # Build tree structure
        tree = []
        for proc in filtered:
            pid = proc["pid"]
            ppid = proc.get("ppid", 0)

            node = {
                "pid": pid,
                "name": proc.get("name", ""),
                "cmdline": proc.get("cmdline", ""),
                "children": [],
            }

            # Find parent and attach
            if ppid and ppid in by_pid:
                parent = by_pid[ppid]
                if "_children" not in parent:
                    parent["_children"] = []
                parent["_children"].append(node)
            else:
                tree.append(node)

        # Convert _children to children in final output
        def attach_children(node_list):
            result = []
            for node in node_list:
                pid = node["pid"]
                if pid in by_pid and "_children" in by_pid[pid]:
                    node["children"] = attach_children(by_pid[pid]["_children"])
                result.append(node)
            return result

        return attach_children(tree)

    def _build_network_summary(self, network_info: dict) -> dict:
        """Build deduplicated network summary."""
        # Dedupe DNS queries
        dns_domains = {}
        for query in network_info.get("dns_queries", []):
            domain = query.get("domain", "")
            if domain and domain not in dns_domains:
                dns_domains[domain] = {
                    "domain": domain,
                    "response": query.get("response", ""),
                    "count": 1,
                }
            elif domain:
                dns_domains[domain]["count"] += 1

        # Dedupe connections
        connections = {}
        for conn in network_info.get("connections", []):
            key = f"{conn.get('remote_ip')}:{conn.get('remote_port')}"
            if key not in connections:
                connections[key] = {
                    "remote_ip": conn.get("remote_ip"),
                    "remote_port": conn.get("remote_port"),
                    "protocol": conn.get("protocol", "tcp"),
                    "count": 1,
                }
            else:
                connections[key]["count"] += 1

        # Dedupe HTTP requests
        http_requests = {}
        for req in network_info.get("http_requests", []):
            key = f"{req.get('method')} {req.get('host')}{req.get('uri', '')}"
            if key not in http_requests:
                http_requests[key] = {
                    "method": req.get("method"),
                    "host": req.get("host"),
                    "uri": req.get("uri"),
                    "count": 1,
                }
            else:
                http_requests[key]["count"] += 1

        return {
            "dns_queries": list(dns_domains.values()),
            "connections": list(connections.values()),
            "http_requests": list(http_requests.values()),
            "total_dns_queries": len(network_info.get("dns_queries", [])),
            "total_connections": len(network_info.get("connections", [])),
        }

    def _build_syscall_summary(self, syscalls: list[dict]) -> dict:
        """Build syscall summary grouped by type."""
        by_name = {}
        by_pid = {}

        for sc in syscalls:
            name = sc.get("name", "")
            pid = sc.get("pid")

            # Count by name
            if name not in by_name:
                by_name[name] = 0
            by_name[name] += 1

            # Count by pid
            if pid not in by_pid:
                by_pid[pid] = []
            if name not in by_pid[pid]:
                by_pid[pid].append(name)

        return {
            "by_type": by_name,
            "by_process": {str(k): v for k, v in by_pid.items()},
            "total_count": len(syscalls),
            "unique_types": list(by_name.keys()),
        }

    def _dedupe_security_events(self, events: list[dict]) -> list[dict]:
        """Deduplicate security events, keeping first occurrence with count."""
        seen = {}
        for event in events:
            key = (event.get("event"), event.get("process"), event.get("pid"))
            if key not in seen:
                seen[key] = {
                    "event": event.get("event"),
                    "process": event.get("process"),
                    "pid": event.get("pid"),
                    "description": event.get("description"),
                    "severity": event.get("severity"),
                    "count": 1,
                }
            else:
                seen[key]["count"] += 1

        return list(seen.values())


def analyze_with_tracee(
    binary_path: str, arch: str = "x86_64", timeout: int = 30
) -> dict[str, Any]:
    """Run Tracee dynamic analysis on a binary."""
    config = TraceeConfig(timeout=timeout)
    analyzer = TraceeAnalyzer(config)
    result = analyzer.analyze(binary_path, arch)

    return {
        "success": result.success,
        "duration_seconds": result.duration_seconds,
        "process_tree": result.process_tree,
        "network_summary": result.network_summary,
        "security_events": result.security_events,
        "syscall_summary": result.syscall_summary,
        "file_activity": result.file_activity,
        "raw_events_count": result.raw_events_count,
        "error": result.error,
        "method": result.method,
        "event_types": result.event_types,
    }
