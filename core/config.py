"""Configuration loader for ThreatScope."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class WorkersConfig:
    stage_1_4: int = 4
    stage_6: int = 4
    dynamic_analysis: int = 2


@dataclass
class GhidraConfig:
    pool_size: int = 1
    docker_image: str = "threatscope/ghidra:latest"
    memory_limit: str = "4g"
    base_http_port: int = 8000
    base_mcp_port: int = 9000
    startup_timeout: int = 60
    base_url: str = "http://localhost:8000"


@dataclass
class ThreatIntelSourceConfig:
    enabled: bool = True
    base_url: str = ""


@dataclass
class ThreatIntelConfig:
    malwarebazaar: ThreatIntelSourceConfig = field(
        default_factory=lambda: ThreatIntelSourceConfig(base_url="https://mb-api.abuse.ch/api/v1/")
    )
    threatfox: ThreatIntelSourceConfig = field(
        default_factory=lambda: ThreatIntelSourceConfig(
            base_url="https://threatfox-api.abuse.ch/api/v1/"
        )
    )
    urlhaus: ThreatIntelSourceConfig = field(
        default_factory=lambda: ThreatIntelSourceConfig(base_url="https://urlhaus-api.abuse.ch/v1/")
    )


@dataclass
class AgentConfig:
    system_prompt_path: str = ""
    max_iterations: int = 20


@dataclass
class AgentsConfig:
    ghidra_agent: AgentConfig = field(
        default_factory=lambda: AgentConfig(system_prompt_path="ai/prompts/ghidra_agent.txt")
    )
    malware_analysis: AgentConfig = field(
        default_factory=lambda: AgentConfig(system_prompt_path="ai/prompts/malware_analysis.txt")
    )


@dataclass
class AnalysisConfig:
    default_timeout: int = 300
    enable_dynamic_analysis: bool = True
    enable_ghidra_analysis: bool = True
    yara_rules_path: str = "rules/yara"


@dataclass
class TasksConfig:
    max_queue_size: int = 100
    result_ttl: int = 86400
    retry_count: int = 3


@dataclass
class Config:
    workers: WorkersConfig = field(default_factory=WorkersConfig)
    ghidra: GhidraConfig = field(default_factory=GhidraConfig)
    threat_intel: ThreatIntelConfig = field(default_factory=ThreatIntelConfig)
    agents: AgentsConfig = field(default_factory=AgentsConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    tasks: TasksConfig = field(default_factory=TasksConfig)


def _dict_to_dataclass(cls: type, data: dict[str, Any]) -> Any:
    """Recursively convert dict to dataclass."""
    if not isinstance(data, dict):
        return data

    field_types = {f.name: f.type for f in cls.__dataclass_fields__.values()}
    kwargs = {}

    for key, value in data.items():
        if key in field_types:
            field_type = field_types[key]
            # Handle nested dataclasses
            if hasattr(field_type, "__dataclass_fields__"):
                kwargs[key] = _dict_to_dataclass(field_type, value)
            else:
                kwargs[key] = value

    return cls(**kwargs)


def load_config(config_path: str | Path | None = None) -> Config:
    """Load configuration from YAML file.

    Args:
        config_path: Path to config file. Defaults to 'config.yaml' in current directory.

    Returns:
        Config object with loaded settings.
    """
    if config_path is None:
        config_path = Path("config.yaml")
    else:
        config_path = Path(config_path)

    if not config_path.exists():
        return Config()

    with open(config_path) as f:
        data = yaml.safe_load(f) or {}

    return _dict_to_dataclass(Config, data)
