"""Binary emulator for dynamic analysis using Docker/QEMU."""

import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Docker image for sandboxed execution
DOCKERFILE_CONTENT = """
FROM ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y qemu-user-static strace file \\
    libc6-mips-cross libc6-mipsel-cross && rm -rf /var/lib/apt/lists/*
RUN useradd -r -u 10000 -s /usr/sbin/nologin -d /tmp sandbox \\
    && mkdir -p /analysis \\
    && chown sandbox:sandbox /analysis \\
    && chmod 700 /analysis
RUN rm -f /usr/bin/wget /usr/bin/curl /bin/nc /bin/netcat /usr/bin/perl \\
    /usr/bin/ssh /usr/bin/scp /usr/bin/sftp /usr/bin/ftp
WORKDIR /analysis
USER sandbox
"""


@dataclass
class EmulationResult:
    """Result of binary emulation."""

    success: bool
    syscalls: list[dict[str, str]] = field(default_factory=list)
    raw_output: str = ""
    error: str | None = None
    method: str = ""  # docker_sdk, docker_cli, host_qemu


@dataclass
class SyscallInfo:
    """Parsed syscall information."""

    name: str
    args: str
    return_value: str = ""


class BinaryEmulator:
    """Emulates binary execution in isolated environment.

    Execution strategy (fallback chain):
    1. Docker SDK - Best isolation
    2. Docker CLI - When SDK unavailable
    3. Host QEMU - When Docker unavailable
    """

    IMAGE_TAG = "threatscope_sandbox:latest"
    EXECUTION_TIMEOUT = 180  # seconds

    # Architecture to QEMU binary mapping
    QEMU_MAPPING = {
        "x86_64": ["x86_64", "x64"],
        "x86": ["i386", "i686"],
        "i386": ["i386", "i686"],
        "i686": ["i686", "i386"],
        "aarch64": ["aarch64", "arm64"],
        "arm64": ["aarch64", "arm64"],
        "arm": ["arm"],
        "mips": ["mips"],
        "mipsel": ["mipsel"],
        "ppc64": ["ppc64", "powerpc64"],
        "riscv64": ["riscv64"],
    }

    def __init__(self, timeout: int | None = None):
        """Initialize emulator.

        Args:
            timeout: Execution timeout in seconds.
        """
        self.timeout = timeout or self.EXECUTION_TIMEOUT
        self._docker_client = None
        self._last_error: str | None = None

        # Try to initialize Docker client
        try:
            import docker

            self._docker_client = docker.from_env()
        except Exception as e:
            logger.warning(f"Docker SDK unavailable: {e}")
            self._last_error = str(e)

    def emulate(self, binary_path: str, arch: str) -> EmulationResult:
        """Emulate binary execution.

        Args:
            binary_path: Path to the binary file.
            arch: Target architecture (x86_64, arm, mips, etc.)

        Returns:
            EmulationResult with syscalls and execution info.
        """
        if not os.path.exists(binary_path):
            return EmulationResult(success=False, error=f"Binary not found: {binary_path}")

        abs_path = os.path.abspath(binary_path)
        arch_lower = arch.lower()

        # Try Docker SDK first
        if self._docker_client:
            result = self._emulate_docker_sdk(abs_path, arch_lower)
            if result.success:
                return result
            logger.info(f"Docker SDK failed: {result.error}, trying CLI fallback")

        # Try Docker CLI
        result = self._emulate_docker_cli(abs_path, arch_lower)
        if result.success:
            return result
        logger.info(f"Docker CLI failed: {result.error}, trying host QEMU")

        # Try host QEMU
        return self._emulate_host_qemu(abs_path, arch_lower)

    def _emulate_docker_sdk(self, binary_path: str, arch: str) -> EmulationResult:
        """Emulate using Docker SDK."""
        if not self._docker_client:
            return EmulationResult(success=False, error="Docker SDK not available")

        container = None
        try:
            # Ensure image exists
            if not self._ensure_docker_image():
                return EmulationResult(success=False, error="Failed to build Docker image")

            basename = os.path.basename(binary_path)
            qemu_bin = f"qemu-{arch}-static"

            # Create container
            container = self._docker_client.containers.run(
                self.IMAGE_TAG,
                command="tail -f /dev/null",
                detach=True,
                working_dir="/analysis",
                privileged=False,
                network_mode="none",
                cap_drop=["ALL"],
                security_opt=["no-new-privileges=true"],
                read_only=False,
                pids_limit=128,
                mem_limit="512m",
                nano_cpus=500_000_000,
            )

            # Copy binary to container
            subprocess.run(
                f"chmod +x {binary_path} && docker cp {binary_path} "
                f"{container.id}:/analysis/{basename}",
                shell=True,
                capture_output=True,
            )

            # Execute with strace
            result = container.exec_run(
                f"{qemu_bin} -strace /analysis/{basename}",
                demux=True,
            )

            output = ""
            if result.output:
                if isinstance(result.output, tuple):
                    output = (result.output[1] or b"").decode("utf-8", errors="replace")
                else:
                    output = result.output.decode("utf-8", errors="replace")

            syscalls = self._parse_strace_output(output)

            return EmulationResult(
                success=True,
                syscalls=syscalls,
                raw_output=output,
                method="docker_sdk",
            )

        except Exception as e:
            return EmulationResult(success=False, error=str(e))

        finally:
            if container:
                try:
                    container.stop(timeout=5)
                    container.remove(force=True)
                except Exception:
                    pass

    def _emulate_docker_cli(self, binary_path: str, arch: str) -> EmulationResult:
        """Emulate using Docker CLI."""
        docker_bin = shutil.which("docker")
        if not docker_bin:
            return EmulationResult(success=False, error="Docker CLI not found")

        container_name = f"threatscope_emul_{os.getpid()}_{int(time.time())}"
        basename = os.path.basename(binary_path)
        qemu_bin = f"qemu-{arch}-static"

        try:
            # Ensure image exists
            inspect = subprocess.run(
                [docker_bin, "image", "inspect", self.IMAGE_TAG],
                capture_output=True,
            )
            if inspect.returncode != 0:
                # Build image
                build = subprocess.run(
                    [docker_bin, "build", "-t", self.IMAGE_TAG, "-"],
                    input=DOCKERFILE_CONTENT.encode(),
                    capture_output=True,
                )
                if build.returncode != 0:
                    return EmulationResult(
                        success=False,
                        error=f"Failed to build image: {build.stderr.decode()[:500]}",
                    )

            # Run container
            run = subprocess.run(
                [
                    docker_bin,
                    "run",
                    "-d",
                    "--name",
                    container_name,
                    "--network",
                    "none",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges=true",
                    "--pids-limit",
                    "128",
                    "--memory",
                    "512m",
                    "--cpus",
                    "0.5",
                    self.IMAGE_TAG,
                    "tail",
                    "-f",
                    "/dev/null",
                ],
                capture_output=True,
            )
            if run.returncode != 0:
                return EmulationResult(
                    success=False,
                    error=f"Failed to start container: {run.stderr.decode()[:500]}",
                )

            # Copy binary
            subprocess.run(
                [
                    docker_bin,
                    "cp",
                    binary_path,
                    f"{container_name}:/analysis/{basename}",
                ],
                capture_output=True,
            )

            # Execute
            exec_result = subprocess.run(
                [
                    docker_bin,
                    "exec",
                    container_name,
                    qemu_bin,
                    "-strace",
                    f"/analysis/{basename}",
                ],
                capture_output=True,
                timeout=self.timeout,
            )

            output = exec_result.stdout.decode(
                "utf-8", errors="replace"
            ) + exec_result.stderr.decode("utf-8", errors="replace")
            syscalls = self._parse_strace_output(output)

            return EmulationResult(
                success=True,
                syscalls=syscalls,
                raw_output=output,
                method="docker_cli",
            )

        except subprocess.TimeoutExpired:
            return EmulationResult(success=False, error="Execution timeout")
        except Exception as e:
            return EmulationResult(success=False, error=str(e))

        finally:
            # Cleanup
            try:
                subprocess.run(
                    [docker_bin, "rm", "-f", container_name],
                    capture_output=True,
                )
            except Exception:
                pass

    def _emulate_host_qemu(self, binary_path: str, arch: str) -> EmulationResult:
        """Emulate using host QEMU (no isolation)."""
        qemu_bin = self._find_qemu_binary(arch)
        if not qemu_bin:
            return EmulationResult(
                success=False,
                error=f"No QEMU binary found for architecture: {arch}",
            )

        try:
            result = subprocess.run(
                [qemu_bin, "-strace", binary_path],
                capture_output=True,
                timeout=self.timeout,
            )

            output = result.stdout.decode("utf-8", errors="replace") + result.stderr.decode(
                "utf-8", errors="replace"
            )
            syscalls = self._parse_strace_output(output)

            return EmulationResult(
                success=True,
                syscalls=syscalls,
                raw_output=output,
                method="host_qemu",
            )

        except subprocess.TimeoutExpired:
            return EmulationResult(success=False, error="Execution timeout")
        except Exception as e:
            return EmulationResult(success=False, error=str(e))

    def _ensure_docker_image(self) -> bool:
        """Ensure Docker image exists."""
        if not self._docker_client:
            return False

        try:
            self._docker_client.images.get(self.IMAGE_TAG)
            return True
        except Exception:
            pass

        # Build image
        try:
            from io import BytesIO

            dockerfile_bytes = BytesIO(DOCKERFILE_CONTENT.encode("utf-8"))
            self._docker_client.images.build(
                fileobj=dockerfile_bytes,
                tag=self.IMAGE_TAG,
                rm=True,
                forcerm=True,
            )
            return True
        except Exception as e:
            logger.error(f"Failed to build Docker image: {e}")
            return False

    def _find_qemu_binary(self, arch: str) -> str | None:
        """Find QEMU binary for architecture."""
        candidates = []
        arch_variants = self.QEMU_MAPPING.get(arch, [arch])

        for variant in arch_variants:
            candidates.append(f"qemu-{variant}-static")
            candidates.append(f"qemu-{variant}")

        for candidate in candidates:
            path = shutil.which(candidate)
            if path:
                return path

        return None

    def _parse_strace_output(self, output: str) -> list[dict[str, str]]:
        """Parse strace output to extract syscalls.

        Args:
            output: Raw strace output.

        Returns:
            List of syscall dictionaries.
        """
        syscall_re = re.compile(
            r"^\s*\d+\s+(?P<name>[a-zA-Z0-9_]+)\((?P<args>.*)\)\s*=",
            re.VERBOSE,
        )

        syscalls = []
        seen = set()

        for line in output.splitlines():
            match = syscall_re.match(line)
            if match:
                name = match.group("name")
                args = match.group("args")

                # Deduplicate by name+args
                key = f"{name}:{args[:100]}"
                if key not in seen:
                    seen.add(key)
                    syscalls.append({"name": name, "args": args})

        return syscalls

    def get_supported_architectures(self) -> list[str]:
        """Get list of supported architectures."""
        return list(self.QEMU_MAPPING.keys())
