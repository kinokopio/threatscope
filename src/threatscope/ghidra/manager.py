"""Ghidra service manager - Auto-start/stop Ghidra HTTP service."""

import logging
import shutil
import subprocess
import time

logger = logging.getLogger(__name__)


class GhidraServiceManager:
    """Manages Ghidra HTTP service lifecycle.

    Automatically starts Ghidra service when needed and stops it after analysis.
    Supports both subprocess mode (local) and Docker mode.
    """

    def __init__(
        self,
        mode: str = "subprocess",
        docker_image: str = "threatscope-ghidra:latest",
        host: str = "localhost",
        port: int = 8080,
        startup_timeout: int = 60,
    ):
        """Initialize Ghidra service manager.

        Args:
            mode: "subprocess" or "docker"
            docker_image: Docker image name (for docker mode)
            host: Service host
            port: Service port
            startup_timeout: Max seconds to wait for service startup
        """
        self.mode = mode
        self.docker_image = docker_image
        self.host = host
        self.port = port
        self.startup_timeout = startup_timeout
        self._process: subprocess.Popen | None = None
        self._container_name: str | None = None

    @property
    def base_url(self) -> str:
        """Get the service base URL."""
        return f"http://{self.host}:{self.port}"

    def start(self) -> bool:
        """Start Ghidra service.

        Returns:
            True if service started successfully.
        """
        if self.is_running():
            logger.info("Ghidra service already running")
            return True

        if self.mode == "subprocess":
            return self._start_subprocess()
        elif self.mode == "docker":
            return self._start_docker()
        else:
            logger.error(f"Unknown mode: {self.mode}")
            return False

    def stop(self) -> None:
        """Stop Ghidra service."""
        if self.mode == "subprocess":
            self._stop_subprocess()
        elif self.mode == "docker":
            self._stop_docker()

    def is_running(self) -> bool:
        """Check if service is running and healthy."""
        import httpx

        try:
            response = httpx.get(f"{self.base_url}/health", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def _start_subprocess(self) -> bool:
        """Start Ghidra service as subprocess."""
        # Check if uvicorn is available
        if not shutil.which("python"):
            logger.error("Python not found")
            return False

        try:
            # Start the HTTP server
            cmd = [
                "python",
                "-m",
                "ghidra_service.http_server",
            ]
            env = {
                "GHIDRA_HTTP_PORT": str(self.port),
            }

            import os

            full_env = os.environ.copy()
            full_env.update(env)

            self._process = subprocess.Popen(
                cmd,
                env=full_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            # Wait for service to be ready
            return self._wait_for_ready()

        except Exception as e:
            logger.error(f"Failed to start Ghidra subprocess: {e}")
            return False

    def _stop_subprocess(self) -> None:
        """Stop Ghidra subprocess."""
        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=10)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None

    def _start_docker(self) -> bool:
        """Start Ghidra service in Docker container."""
        if not shutil.which("docker"):
            logger.error("Docker not found")
            return False

        import uuid

        self._container_name = f"ghidra-service-{uuid.uuid4().hex[:8]}"

        try:
            cmd = [
                "docker",
                "run",
                "-d",
                "--name",
                self._container_name,
                "-p",
                f"{self.port}:8000",
                "--rm",
                self.docker_image,
            ]

            result = subprocess.run(cmd, capture_output=True, timeout=30)
            if result.returncode != 0:
                logger.error(f"Failed to start Ghidra container: {result.stderr.decode()}")
                return False

            return self._wait_for_ready()

        except Exception as e:
            logger.error(f"Failed to start Ghidra container: {e}")
            return False

    def _stop_docker(self) -> None:
        """Stop Ghidra Docker container."""
        if self._container_name:
            try:
                subprocess.run(
                    ["docker", "stop", self._container_name],
                    capture_output=True,
                    timeout=15,
                )
            except Exception:
                pass
            self._container_name = None

    def _wait_for_ready(self) -> bool:
        """Wait for service to become ready."""
        import httpx

        start_time = time.time()
        while time.time() - start_time < self.startup_timeout:
            try:
                response = httpx.get(f"{self.base_url}/health", timeout=5)
                if response.status_code == 200:
                    logger.info(f"Ghidra service ready at {self.base_url}")
                    return True
            except Exception:
                pass
            time.sleep(1)

        logger.error(f"Ghidra service failed to start within {self.startup_timeout}s")
        return False

    def __enter__(self):
        """Context manager entry."""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop()
