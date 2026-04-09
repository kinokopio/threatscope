# tests/test_threat_intel_providers.py
"""Unit tests for threat intel provider architecture."""
import pytest

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)


def test_threat_intel_result_defaults():
    result = ThreatIntelResult(source="test", found=True, data={"key": "val"})
    assert result.source == "test"
    assert result.found is True
    assert result.data == {"key": "val"}
    assert result.error is None


def test_threat_intel_result_with_error():
    result = ThreatIntelResult(source="test", found=False, data={}, error="timeout")
    assert result.error == "timeout"
    assert result.found is False


class ConcreteProvider(BaseThreatIntelProvider):
    name = "concrete"

    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        return ThreatIntelResult(source=self.name, found=False, data={})


@pytest.mark.asyncio
async def test_base_provider_query_ioc_default():
    """query_ioc 默认返回 found=False，不抛异常。"""
    provider = ConcreteProvider()
    result = await provider.query_ioc("example.com", "domain")
    assert result.found is False
    assert result.source == "concrete"


def test_abstract_provider_cannot_instantiate():
    """未实现 query_hash 的子类无法实例化。"""
    with pytest.raises(TypeError):
        BaseThreatIntelProvider()  # type: ignore


def test_provider_subclass_without_name_raises():
    """Subclass that omits 'name' is rejected at class definition time."""
    with pytest.raises(TypeError, match="must define a 'name'"):
        class NoNameProvider(BaseThreatIntelProvider):
            async def query_hash(self, hash_value: str) -> ThreatIntelResult:
                return ThreatIntelResult(source="x", found=False, data={})


def test_provider_subclass_with_non_str_name_raises():
    """Subclass that sets name to a non-str is rejected at class definition time."""
    with pytest.raises(TypeError, match="must define a 'name'"):
        class IntNameProvider(BaseThreatIntelProvider):
            name = 42  # type: ignore
            async def query_hash(self, hash_value: str) -> ThreatIntelResult:
                return ThreatIntelResult(source="x", found=False, data={})
