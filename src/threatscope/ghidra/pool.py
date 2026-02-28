"""GhidraInstancePool - Docker-based Ghidra instance pool management."""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx

logger = logging.getLogger(__name__)

try:
    from docker.models.containers import Container

    import docker
except ImportError:
    docker = None
    Container = None
    # Only warn if not running inside a container (pool management is done externally)
    import os
    if not os.path.exists("/.dockerenv"):
        logger.warning("docker package not available, pool management disabled")

@dataclass
class GhidraInstance:
    """Represents a single Ghidra instance."""

    id: str
    container_id: str | None
    http_port: int
    mcp_port: int
    status: str = "idle"  # idle, busy, error, starting
    current_sample: str | None = None
    created_at: datetime = field(default_factory=datetime.now)
    last_used: datetime = field(default_factory=datetime.now)
    error_count: int = 0

    @property
    def http_url(self) -> str:
        return f"http://localhost:{self.http_port}"

    @property
    def mcp_url(self) -> str:
        return f"http://localhost:{self.mcp_port}/mcp"


@dataclass
class PoolConfig:
    """Configuration for Ghidra instance pool."""

    pool_size: int = 1
    docker_image: str = "threatscope/ghidra:latest"
    base_http_port: int = 8000
    base_mcp_port: int = 9000
    memory_limit: str = "4g"
    startup_timeout: int = 120
    health_check_interval: int = 30
    max_error_count: int = 3


class GhidraInstancePool:
    """Manages a pool of Ghidra Docker instances.

    Features:
    - Automatic instance creation and cleanup
    - Health checking and recovery
    - Instance acquisition and release
    - Graceful shutdown
    """

    def __init__(self, config: PoolConfig | None = None):
        """Initialize the pool.

        Args:
            config: Pool configuration.
        """
        self.config = config or PoolConfig()
        self._instances: dict[str, GhidraInstance] = {}
        self._available: asyncio.Queue[str] = asyncio.Queue()
        self._lock = asyncio.Lock()
        self._running = False
        self._health_task: asyncio.Task | None = None
        self._docker_client = None

        if docker:
            try:
                self._docker_client = docker.from_env()
            except Exception as e:
                logger.warning(f"Docker client initialization failed: {e}")

    async def initialize(self) -> bool:
        """Initialize the pool and create instances.

        Returns:
            True if at least one instance was created.
        """
        if not self._docker_client:
            logger.error("Docker client not available, cannot initialize pool")
            return False

        self._running = True
        success_count = 0

        for i in range(self.config.pool_size):
            try:
                instance = await self._create_instance(i)
                if instance:
                    self._instances[instance.id] = instance
                    await self._available.put(instance.id)
                    success_count += 1
            except Exception as e:
                logger.error(f"Failed to create instance {i}: {e}")

        if success_count > 0:
            # Start health check task
            self._health_task = asyncio.create_task(self._health_check_loop())
            logger.info(f"Pool initialized with {success_count}/{self.config.pool_size} instances")

        return success_count > 0

    async def shutdown(self) -> None:
        """Shutdown the pool and cleanup all instances."""
        self._running = False

        # Stop health check
        if self._health_task:
            self._health_task.cancel()
            try:
                await self._health_task
            except asyncio.CancelledError:
                pass

        # Stop all containers
        for instance in list(self._instances.values()):
            await self._destroy_instance(instance)

        self._instances.clear()
        logger.info("Pool shutdown complete")

    async def acquire(self, timeout: float | None = None) -> GhidraInstance | None:
        """Acquire an available instance.

        Args:
            timeout: Maximum time to wait for an instance.

        Returns:
            GhidraInstance or None if timeout.
        """
        try:
            if timeout:
                instance_id = await asyncio.wait_for(self._available.get(), timeout=timeout)
            else:
                instance_id = await self._available.get()

            async with self._lock:
                instance = self._instances.get(instance_id)
                if instance:
                    instance.status = "busy"
                    instance.last_used = datetime.now()
                    return instance

            return None

        except asyncio.TimeoutError:
            return None

    async def release(self, instance: GhidraInstance) -> None:
        """Release an instance back to the pool.

        Args:
            instance: The instance to release.
        """
        async with self._lock:
            if instance.id in self._instances:
                instance.status = "idle"
                instance.current_sample = None
                await self._available.put(instance.id)

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics."""
        return {
            "total": len(self._instances),
            "available": self._available.qsize(),
            "busy": sum(1 for i in self._instances.values() if i.status == "busy"),
            "error": sum(1 for i in self._instances.values() if i.status == "error"),
            "instances": [
                {
                    "id": i.id,
                    "status": i.status,
                    "http_port": i.http_port,
                    "error_count": i.error_count,
                }
                for i in self._instances.values()
            ],
        }

    # --- Internal methods ---

    async def _create_instance(self, index: int) -> GhidraInstance | None:
        """Create a new Ghidra instance."""
        if not self._docker_client:
            return None

        http_port = self.config.base_http_port + index
        mcp_port = self.config.base_mcp_port + index
        instance_id = f"ghidra_{index}"

        logger.info(f"Creating Ghidra instance {instance_id} on ports {http_port}/{mcp_port}")

        try:
            # Check if container already exists
            try:
                existing = self._docker_client.containers.get(f"threatscope_{instance_id}")
                existing.remove(force=True)
            except docker.errors.NotFound:
                pass

            # Create container
            container = self._docker_client.containers.run(
                self.config.docker_image,
                name=f"threatscope_{instance_id}",
                detach=True,
                ports={
                    "8000/tcp": http_port,
                    "9000/tcp": mcp_port,
                },
                mem_limit=self.config.memory_limit,
                environment={
                    "GHIDRA_HTTP_PORT": "8000",
                    "GHIDRA_MCP_PORT": "9000",
                },
            )

            instance = GhidraInstance(
                id=instance_id,
                container_id=container.id,
                http_port=http_port,
                mcp_port=mcp_port,
                status="starting",
            )

            # Wait for service to be ready
            if await self._wait_for_ready(instance):
                instance.status = "idle"
                logger.info(f"Instance {instance_id} ready")
                return instance
            else:
                logger.error(f"Instance {instance_id} failed to start")
                await self._destroy_instance(instance)
                return None

        except Exception as e:
            logger.error(f"Failed to create instance {instance_id}: {e}")
            return None

    async def _destroy_instance(self, instance: GhidraInstance) -> None:
        """Destroy a Ghidra instance."""
        if not self._docker_client or not instance.container_id:
            return

        try:
            container = self._docker_client.containers.get(instance.container_id)
            container.stop(timeout=10)
            container.remove(force=True)
            logger.info(f"Instance {instance.id} destroyed")
        except Exception as e:
            logger.warning(f"Error destroying instance {instance.id}: {e}")

    async def _wait_for_ready(self, instance: GhidraInstance) -> bool:
        """Wait for instance to be ready."""
        start_time = asyncio.get_event_loop().time()

        while asyncio.get_event_loop().time() - start_time < self.config.startup_timeout:
            try:
                async with httpx.AsyncClient() as client:
                    resp = await client.get(
                        f"{instance.http_url}/health",
                        timeout=5.0,
                    )
                    if resp.status_code == 200:
                        return True
            except Exception:
                pass

            await asyncio.sleep(2)

        return False

    async def _health_check_loop(self) -> None:
        """Periodic health check for all instances."""
        while self._running:
            try:
                await asyncio.sleep(self.config.health_check_interval)

                for instance in list(self._instances.values()):
                    if instance.status == "busy":
                        continue

                    healthy = await self._check_instance_health(instance)
                    if not healthy:
                        instance.error_count += 1
                        if instance.error_count >= self.config.max_error_count:
                            logger.warning(f"Instance {instance.id} unhealthy, recreating")
                            await self._recreate_instance(instance)
                    else:
                        instance.error_count = 0

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Health check error: {e}")

    async def _check_instance_health(self, instance: GhidraInstance) -> bool:
        """Check if an instance is healthy."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{instance.http_url}/health",
                    timeout=10.0,
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def _recreate_instance(self, instance: GhidraInstance) -> None:
        """Recreate a failed instance."""
        async with self._lock:
            # Remove from available queue if present
            # (This is a simplified approach - in production you'd want a proper queue management)

            # Destroy old instance
            await self._destroy_instance(instance)

            # Extract index from id
            try:
                index = int(instance.id.split("_")[1])
            except (IndexError, ValueError):
                index = 0

            # Create new instance
            new_instance = await self._create_instance(index)
            if new_instance:
                self._instances[new_instance.id] = new_instance
                await self._available.put(new_instance.id)
            else:
                # Remove failed instance from pool
                self._instances.pop(instance.id, None)


class SingleInstancePool:
    """Simplified pool for single Ghidra instance (no Docker management).

    Use this when Ghidra service is managed externally.
    """

    def __init__(self, http_url: str = "http://localhost:8000"):
        """Initialize single instance pool.

        Args:
            http_url: URL of the Ghidra HTTP service.
        """
        self._instance = GhidraInstance(
            id="ghidra_0",
            container_id=None,
            http_port=8000,
            mcp_port=9000,
        )
        self._instance._http_url = http_url
        self._lock = asyncio.Lock()
        self._available = True

    async def initialize(self) -> bool:
        """Check if the service is available."""
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{self._instance.http_url}/health",
                    timeout=10.0,
                )
                return resp.status_code == 200
        except Exception:
            return False

    async def shutdown(self) -> None:
        """No-op for single instance."""
        pass

    async def acquire(self, timeout: float | None = None) -> GhidraInstance | None:
        """Acquire the instance."""
        async with self._lock:
            if self._available:
                self._available = False
                self._instance.status = "busy"
                return self._instance
            return None

    async def release(self, instance: GhidraInstance) -> None:
        """Release the instance."""
        async with self._lock:
            self._available = True
            self._instance.status = "idle"

    def get_stats(self) -> dict[str, Any]:
        """Get pool statistics."""
        return {
            "total": 1,
            "available": 1 if self._available else 0,
            "busy": 0 if self._available else 1,
            "instances": [
                {
                    "id": self._instance.id,
                    "status": self._instance.status,
                    "http_port": self._instance.http_port,
                }
            ],
        }
