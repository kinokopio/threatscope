"""Application configuration using Pydantic Settings.

This module provides type-safe configuration management with:
- Environment variable support with prefixes
- .env file loading
- Nested configuration groups
- Validation and defaults
"""

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class WorkersSettings(BaseSettings):
    """Worker pool configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_WORKERS_")

    stage_1_4: int = Field(default=4, ge=1, le=32, description="Parallel workers for Stage 1-4")
    stage_6: int = Field(default=4, ge=1, le=32, description="Parallel workers for Stage 6")
    dynamic_analysis: int = Field(default=2, ge=1, le=8, description="Dynamic analysis workers")


class GhidraSettings(BaseSettings):
    """Ghidra service configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_GHIDRA_")

    pool_size: int = Field(default=1, ge=1, le=4, description="Ghidra instance pool size")
    docker_image: str = Field(default="threatscope/ghidra:latest")
    memory_limit: str = Field(default="4g")
    base_http_port: int = Field(default=8080, ge=1024, le=65535)
    base_mcp_port: int = Field(default=9000, ge=1024, le=65535)
    startup_timeout: int = Field(default=60, ge=10, le=300)
    service_mode: Literal["subprocess", "docker"] = Field(default="subprocess")
    service_host: str = Field(default="localhost")

    @property
    def base_url(self) -> str:
        """Get the Ghidra service base URL."""
        return f"http://{self.service_host}:{self.base_http_port}"


class ThreatIntelSettings(BaseSettings):
    """Threat intelligence services configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_THREAT_INTEL_")

    malwarebazaar_url: str = Field(default="https://mb-api.abuse.ch/api/v1/")
    malwarebazaar_enabled: bool = Field(default=True)
    threatfox_url: str = Field(default="https://threatfox-api.abuse.ch/api/v1/")
    threatfox_enabled: bool = Field(default=True)
    urlhaus_url: str = Field(default="https://urlhaus-api.abuse.ch/v1/")
    urlhaus_enabled: bool = Field(default=True)
    virustotal_enabled: bool = Field(default=False)
    virustotal_api_key: SecretStr = Field(default="")
    tix_enabled: bool = Field(default=False)
    tix_app_key: SecretStr = Field(default="")


class AgentSettings(BaseSettings):
    """AI agent configuration."""

    system_prompt_path: str = ""
    max_iterations: int = Field(default=20, ge=1, le=100)


class AgentsSettings(BaseSettings):
    """All AI agents configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_AGENTS_")

    ghidra_system_prompt: str = Field(default="ai/prompts/ghidra_agent.txt")
    ghidra_max_iterations: int = Field(default=20, ge=1, le=100)
    malware_system_prompt: str = Field(default="ai/prompts/malware_analysis.txt")
    malware_max_iterations: int = Field(default=20, ge=1, le=100)


class AnalysisSettings(BaseSettings):
    """Analysis pipeline configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_ANALYSIS_")

    default_timeout: int = Field(default=300, ge=30, le=3600)
    dynamic_analysis_timeout: int = Field(default=30, ge=10, le=300)
    enable_dynamic_analysis: bool = Field(default=True)
    enable_ghidra_analysis: bool = Field(default=True)
    yara_rules_path: str = Field(default="rules/yara_full")


class TraceeSettings(BaseSettings):
    """Tracee dynamic analysis configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_TRACEE_")

    image: str = Field(default="aquasec/tracee:latest")
    sandbox_image: str = Field(default="ubuntu:22.04")
    output_dir: str = Field(default="/tmp/tracee-output")
    enable_network_capture: bool = Field(default=True)
    enable_file_capture: bool = Field(default=True)


class DiecSettings(BaseSettings):
    """diec file type identification service configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_DIEC_")

    url: str = Field(default="http://localhost:8082", description="diec HTTP service URL")
    timeout: int = Field(default=60, ge=5, le=300, description="Request timeout in seconds")
    enabled: bool = Field(default=True, description="Enable diec service")


class CapaSettings(BaseSettings):
    """capa capability detection configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_CAPA_")

    rules_path: str = Field(default="rules/capa", description="Path to capa rules directory")
    timeout: int = Field(default=600, ge=10, le=1800, description="Analysis timeout in seconds")
    enabled: bool = Field(default=True, description="Enable capa analysis")


class GDBSettings(BaseSettings):
    """GDB dynamic analysis configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_GDB_")

    enabled: bool = Field(default=False, description="Enable GDB dynamic analysis")
    service_mode: Literal["stdio", "http", "sse"] = Field(
        default="stdio", description="MCP server mode: stdio (subprocess), http, or sse (Docker)"
    )
    mcp_command: list[str] = Field(
        default=["gdb-mcp-server"],
        description="Command to start GDB MCP server (stdio mode only)",
    )
    mcp_url: str = Field(
        default="http://localhost:8081/sse",
        description="GDB MCP server URL (http/sse mode)",
    )
    gdb_path: str = Field(default="gdb", description="Path to GDB executable")
    timeout: int = Field(default=300, ge=30, le=1800, description="Analysis timeout in seconds")
    gdbserver_host: str = Field(
        default="localhost", description="GDBServer host for remote debugging"
    )
    gdbserver_port: int = Field(default=1234, ge=1024, le=65535, description="GDBServer port")


class TasksSettings(BaseSettings):
    """Task queue configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_TASKS_")

    max_queue_size: int = Field(default=100, ge=10, le=10000)
    result_ttl: int = Field(default=86400, ge=3600, description="Result TTL in seconds")
    retry_count: int = Field(default=3, ge=0, le=10)


class LLMSettings(BaseSettings):
    """LLM/AI model configuration."""

    model_config = SettingsConfigDict(env_prefix="ANTHROPIC_")

    api_key: str = Field(default="", description="Anthropic API key")
    base_url: str = Field(default="", description="Custom API base URL")
    model: str = Field(default="claude-sonnet-4-20250514")
    timeout: int = Field(default=60, ge=10, le=600)


class DatabaseSettings(BaseSettings):
    """Database configuration."""

    model_config = SettingsConfigDict(env_prefix="THREATSCOPE_DB_")

    path: str = Field(default=".threatscope/tasks.db")
    timeout: float = Field(default=30.0, ge=1.0, le=120.0)


class APISettings(BaseSettings):
    """API server configuration."""

    model_config = SettingsConfigDict(
        env_prefix="THREATSCOPE_API_",
        populate_by_name=True,  # Allow both field name and alias
    )

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1024, le=65535)
    # Store as string to avoid pydantic-settings JSON parsing issues
    cors_origins_str: str = Field(
        default="http://localhost:5173,http://localhost:5174,http://127.0.0.1:5173,http://127.0.0.1:5174",
        validation_alias="THREATSCOPE_API_CORS_ORIGINS",
    )
    debug: bool = Field(default=False)
    docs_enabled: bool = Field(default=True)

    @property
    def cors_origins(self) -> list[str]:
        """Parse CORS origins from comma-separated string."""
        return [origin.strip() for origin in self.cors_origins_str.split(",") if origin.strip()]


class Settings(BaseSettings):
    """Main application settings.

    All settings can be configured via:
    - Environment variables (with THREATSCOPE_ prefix)
    - .env file
    - config.yaml file (legacy support)

    Example:
        THREATSCOPE_API_PORT=8080
        THREATSCOPE_GHIDRA_BASE_URL=http://ghidra:8000
        ANTHROPIC_API_KEY=sk-...
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="THREATSCOPE_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Environment
    environment: Literal["local", "staging", "production"] = Field(default="local")
    debug: bool = Field(default=False)

    # Nested settings (loaded from sub-prefixes)
    workers: WorkersSettings = Field(default_factory=WorkersSettings)
    ghidra: GhidraSettings = Field(default_factory=GhidraSettings)
    gdb: GDBSettings = Field(default_factory=GDBSettings)
    diec: DiecSettings = Field(default_factory=DiecSettings)
    capa: CapaSettings = Field(default_factory=CapaSettings)
    threat_intel: ThreatIntelSettings = Field(default_factory=ThreatIntelSettings)
    agents: AgentsSettings = Field(default_factory=AgentsSettings)
    analysis: AnalysisSettings = Field(default_factory=AnalysisSettings)
    tracee: TraceeSettings = Field(default_factory=TraceeSettings)
    tasks: TasksSettings = Field(default_factory=TasksSettings)
    llm: LLMSettings = Field(default_factory=LLMSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    api: APISettings = Field(default_factory=APISettings)

    @property
    def show_docs(self) -> bool:
        """Whether to show API documentation."""
        return self.environment in ("local", "staging") and self.api.docs_enabled


@lru_cache
def get_settings() -> Settings:
    """Get cached application settings.

    Returns:
        Settings instance (cached after first call).

    Example:
        settings = get_settings()
        print(settings.api.port)
    """
    return Settings()


def load_from_yaml(yaml_path: str | Path = "config.yaml") -> Settings:
    """Load settings with YAML file fallback for legacy support.

    This function provides backward compatibility with the old config.yaml format.
    Environment variables always take precedence over YAML values.

    Args:
        yaml_path: Path to legacy config.yaml file.

    Returns:
        Settings instance.
    """
    import os

    import yaml

    yaml_path = Path(yaml_path)
    if not yaml_path.exists():
        return get_settings()

    with open(yaml_path) as f:
        yaml_data = yaml.safe_load(f) or {}

    # Map YAML keys to environment variables (env vars take precedence)
    env_mappings = {
        "ghidra.base_url": "THREATSCOPE_GHIDRA_BASE_URL",
        "ghidra.pool_size": "THREATSCOPE_GHIDRA_POOL_SIZE",
        "analysis.enable_ghidra_analysis": "THREATSCOPE_ANALYSIS_ENABLE_GHIDRA_ANALYSIS",
        "analysis.enable_dynamic_analysis": "THREATSCOPE_ANALYSIS_ENABLE_DYNAMIC_ANALYSIS",
        "workers.stage_1_4": "THREATSCOPE_WORKERS_STAGE_1_4",
    }

    def get_nested(data: dict, path: str):
        """Get nested value from dict using dot notation."""
        keys = path.split(".")
        for key in keys:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                return None
        return data

    # Set env vars from YAML if not already set
    for yaml_key, env_key in env_mappings.items():
        if not os.environ.get(env_key):
            value = get_nested(yaml_data, yaml_key)
            if value is not None:
                os.environ[env_key] = str(value)

    # Clear cache and reload
    get_settings.cache_clear()
    return get_settings()
