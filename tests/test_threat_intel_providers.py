# tests/test_threat_intel_providers.py
"""Unit tests for threat intel provider architecture."""

from unittest.mock import AsyncMock, MagicMock, patch

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


class TestMalwareBazaarProvider:
    @pytest.mark.asyncio
    async def test_query_hash_found(self):
        from src.threatscope.analysis.services.threat_intel.providers.malwarebazaar import (
            MalwareBazaarProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "signature": "Emotet",
                    "tags": ["emotet", "trojan"],
                    "first_seen": "2023-01-01 00:00:00",
                    "file_type": "exe",
                    "delivery_method": "email",
                    "intelligence": {"downloads": 5},
                }
            ],
        }

        provider = MalwareBazaarProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.source == "malwarebazaar"
        assert result.found is True
        assert result.data["family"] == "Emotet"
        assert result.data["tags"] == ["emotet", "trojan"]
        assert result.error is None

    @pytest.mark.asyncio
    async def test_query_hash_not_found(self):
        from src.threatscope.analysis.services.threat_intel.providers.malwarebazaar import (
            MalwareBazaarProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"query_status": "hash_not_found"}

        provider = MalwareBazaarProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert result.error is None

    @pytest.mark.asyncio
    async def test_query_hash_network_error(self):
        from src.threatscope.analysis.services.threat_intel.providers.malwarebazaar import (
            MalwareBazaarProvider,
        )

        provider = MalwareBazaarProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.side_effect = Exception("connection refused")

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert "connection refused" in result.error


class TestThreatFoxProvider:
    @pytest.mark.asyncio
    async def test_query_hash_found(self):
        from src.threatscope.analysis.services.threat_intel.providers.threatfox import (
            ThreatFoxProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [{"ioc": "abc123", "malware": "Emotet", "confidence_level": 90}],
        }

        provider = ThreatFoxProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.source == "threatfox"
        assert result.found is True
        assert len(result.data["iocs"]) == 1

    @pytest.mark.asyncio
    async def test_query_hash_not_found(self):
        from src.threatscope.analysis.services.threat_intel.providers.threatfox import (
            ThreatFoxProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"query_status": "no_result"}

        provider = ThreatFoxProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False

    @pytest.mark.asyncio
    async def test_query_ioc_found(self):
        from src.threatscope.analysis.services.threat_intel.providers.threatfox import (
            ThreatFoxProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "data": [{"ioc": "evil.com", "ioc_type": "domain"}],
        }

        provider = ThreatFoxProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_ioc("evil.com", "domain")

        assert result.found is True
        assert result.data["ioc"] == "evil.com"


class TestURLhausProvider:
    @pytest.mark.asyncio
    async def test_query_hash_not_supported(self):
        """URLhaus 不支持 hash 查询，返回 found=False。"""
        from src.threatscope.analysis.services.threat_intel.providers.urlhaus import (
            URLhausProvider,
        )

        provider = URLhausProvider()
        result = await provider.query_hash("abc123sha256")
        assert result.found is False
        assert result.source == "urlhaus"

    @pytest.mark.asyncio
    async def test_query_ioc_url_found(self):
        """URLhaus 找到 URL IOC，返回 found=True 及 threat 字段。"""
        from src.threatscope.analysis.services.threat_intel.providers.urlhaus import (
            URLhausProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "query_status": "ok",
            "threat": "malware_download",
            "tags": ["emotet"],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/123/",
            "date_added": "2023-01-01 00:00:00 UTC",
        }

        provider = URLhausProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_ioc("http://evil.com/payload.exe", "url")

        assert result.found is True
        assert result.data["threat"] == "malware_download"
        assert result.data["url"] == "http://evil.com/payload.exe"

    @pytest.mark.asyncio
    async def test_query_ioc_url_not_found(self):
        """URLhaus 未找到 URL IOC，返回 found=False。"""
        from src.threatscope.analysis.services.threat_intel.providers.urlhaus import (
            URLhausProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {"query_status": "no_results"}

        provider = URLhausProvider()
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_ioc("http://clean.com", "url")

        assert result.found is False
        assert result.data.get("url") == "http://clean.com"

    @pytest.mark.asyncio
    async def test_query_ioc_non_url_not_supported(self):
        from src.threatscope.analysis.services.threat_intel.providers.urlhaus import (
            URLhausProvider,
        )

        provider = URLhausProvider()
        result = await provider.query_ioc("192.168.1.1", "ip:port")
        assert result.found is False
        assert result.source == "urlhaus"
        assert result.data.get("ioc") == "192.168.1.1"
