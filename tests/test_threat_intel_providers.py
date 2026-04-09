# tests/test_threat_intel_providers.py
"""Unit tests for threat intel provider architecture."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
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


class TestVirusTotalProvider:
    @pytest.mark.asyncio
    async def test_query_hash_found_malicious(self):
        from src.threatscope.analysis.services.threat_intel.providers.virustotal import (
            VirusTotalProvider,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 45,
                        "suspicious": 2,
                        "undetected": 10,
                        "harmless": 0,
                    },
                    "meaningful_name": "emotet.exe",
                    "popular_threat_classification": {
                        "suggested_threat_label": "trojan.emotet/generic"
                    },
                }
            }
        }

        provider = VirusTotalProvider(api_key="test-key")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response

            result = await provider.query_hash(
                "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
            )

        assert result.source == "virustotal"
        assert result.found is True
        assert result.data["malicious"] == 45
        assert result.data["meaningful_name"] == "emotet.exe"
        assert result.error is None

        # 确认 Header 包含 API Key
        call_kwargs = mock_client.get.call_args
        assert call_kwargs.kwargs["headers"]["x-apikey"] == "test-key"

    @pytest.mark.asyncio
    async def test_query_hash_found_but_clean(self):
        """HTTP 200 但 malicious=0，返回 found=False。"""
        from src.threatscope.analysis.services.threat_intel.providers.virustotal import (
            VirusTotalProvider,
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 70,
                        "harmless": 5,
                    },
                    "meaningful_name": "putty.exe",
                    "popular_threat_classification": None,
                }
            }
        }

        provider = VirusTotalProvider(api_key="test-key")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert result.data["malicious"] == 0

    @pytest.mark.asyncio
    async def test_query_hash_not_in_vt(self):
        """HTTP 404 表示 VT 中无记录。"""
        from src.threatscope.analysis.services.threat_intel.providers.virustotal import (
            VirusTotalProvider,
        )

        mock_response = MagicMock()
        mock_response.status_code = 404

        provider = VirusTotalProvider(api_key="test-key")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert result.error is None

    @pytest.mark.asyncio
    async def test_query_hash_network_error(self):
        from src.threatscope.analysis.services.threat_intel.providers.virustotal import (
            VirusTotalProvider,
        )

        provider = VirusTotalProvider(api_key="test-key")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.get.side_effect = Exception("SSL error")

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert "SSL error" in result.error

    @pytest.mark.asyncio
    async def test_query_hash_server_error(self):
        """HTTP 5xx 返回 found=False，error 包含状态码。"""
        from src.threatscope.analysis.services.threat_intel.providers.virustotal import (
            VirusTotalProvider,
        )

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "500 Internal Server Error", request=MagicMock(), response=mock_response
        )

        provider = VirusTotalProvider(api_key="test-key")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.get.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert result.error is not None
        assert "500" in result.error


class TestTencentTIXProvider:
    @pytest.mark.asyncio
    async def test_query_hash_found_malicious(self):
        from src.threatscope.analysis.services.threat_intel.providers.tencent_tix import (
            TencentTIXProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "return_code": 0,
            "return_msg": "success",
            "ver": "3.0",
            "data": {
                "summary": {
                    "risk_level": 4,
                    "md5": "bd5818a8eb45efa6dbf3f16890bcd636",
                    "file_type": "exe",
                    "taskid": "20241128000394442",
                },
                "vdc_infos": {
                    "virusname": "Trojan.Win32.Emotet",
                    "threat_level": 4,
                    "scan_modi_time": "2024-11-28 11:53:24",
                },
                "tag_info": [{"tag": "远控木马", "confidence": 90}],
            },
        }

        provider = TencentTIXProvider(app_key="test-appkey")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("bd5818a8eb45efa6dbf3f16890bcd636")

        assert result.source == "tencent_tix"
        assert result.found is True
        assert result.data["risk_level"] == 4
        assert result.data["virusname"] == "Trojan.Win32.Emotet"
        assert result.error is None
        assert result.data["task_id"] == "20241128000394442"

        # 确认 appkey 在请求 body 中，而非 header
        call_kwargs = mock_client.post.call_args
        assert call_kwargs.kwargs["json"]["c_appkey"] == "test-appkey"
        assert "c_appkey" not in str(call_kwargs.kwargs.get("params", {}))

    @pytest.mark.asyncio
    async def test_query_hash_found_but_clean(self):
        """risk_level=0 返回 found=False。"""
        from src.threatscope.analysis.services.threat_intel.providers.tencent_tix import (
            TencentTIXProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "return_code": 0,
            "return_msg": "success",
            "ver": "3.0",
            "data": {
                "summary": {"risk_level": 0, "md5": "abc123", "file_type": "exe"},
                "vdc_infos": {"virusname": "", "threat_level": 0},
                "tag_info": None,
            },
        }

        provider = TencentTIXProvider(app_key="test-appkey")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert result.data["risk_level"] == 0

    @pytest.mark.asyncio
    async def test_query_hash_api_error(self):
        """return_code != 0 返回 found=False，error 含 return_msg。"""
        from src.threatscope.analysis.services.threat_intel.providers.tencent_tix import (
            TencentTIXProvider,
        )

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "return_code": 1001,
            "return_msg": "invalid appkey",
            "ver": "3.0",
        }

        provider = TencentTIXProvider(app_key="bad-key")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert "invalid appkey" in result.error

    @pytest.mark.asyncio
    async def test_query_hash_network_error(self):
        from src.threatscope.analysis.services.threat_intel.providers.tencent_tix import (
            TencentTIXProvider,
        )

        provider = TencentTIXProvider(app_key="test-appkey")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.side_effect = Exception("connection timeout")

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert "connection timeout" in result.error

    @pytest.mark.asyncio
    async def test_query_hash_server_error(self):
        """HTTP 5xx 返回 found=False，error 包含状态码。"""
        import httpx as httpx_module

        from src.threatscope.analysis.services.threat_intel.providers.tencent_tix import (
            TencentTIXProvider,
        )

        mock_response = MagicMock()
        mock_response.status_code = 503
        mock_response.text = "Service Unavailable"
        mock_response.raise_for_status.side_effect = httpx_module.HTTPStatusError(
            "503 Service Unavailable", request=MagicMock(), response=mock_response
        )

        provider = TencentTIXProvider(app_key="test-appkey")
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client_class.return_value.__aenter__.return_value = mock_client
            mock_client.post.return_value = mock_response

            result = await provider.query_hash("abc123")

        assert result.found is False
        assert result.error is not None
        assert "503" in result.error


class TestThreatIntelService:
    @pytest.mark.asyncio
    async def test_query_hash_aggregates_all_providers(self):
        from src.threatscope.analysis.services.threat_intel.base import ThreatIntelResult
        from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService

        provider_a = MagicMock()
        provider_a.name = "source_a"
        provider_a.query_hash = AsyncMock(
            return_value=ThreatIntelResult(source="source_a", found=True, data={"x": 1})
        )

        provider_b = MagicMock()
        provider_b.name = "source_b"
        provider_b.query_hash = AsyncMock(
            return_value=ThreatIntelResult(source="source_b", found=False, data={})
        )

        service = ThreatIntelService(providers=[provider_a, provider_b])
        results = await service.query_hash("abc123")

        assert "source_a" in results
        assert "source_b" in results
        assert results["source_a"].found is True
        assert results["source_b"].found is False
        provider_a.query_hash.assert_called_once_with("abc123")
        provider_b.query_hash.assert_called_once_with("abc123")

    @pytest.mark.asyncio
    async def test_query_hash_provider_failure_isolated(self):
        """一个 provider 抛异常，不影响其他 provider 的结果。"""
        from src.threatscope.analysis.services.threat_intel.base import ThreatIntelResult
        from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService

        good_provider = MagicMock()
        good_provider.name = "good"
        good_provider.query_hash = AsyncMock(
            return_value=ThreatIntelResult(source="good", found=True, data={})
        )

        bad_provider = MagicMock()
        bad_provider.name = "bad"
        bad_provider.query_hash = AsyncMock(side_effect=RuntimeError("provider crashed"))

        service = ThreatIntelService(providers=[good_provider, bad_provider])
        results = await service.query_hash("abc123")

        assert "good" in results
        assert results["good"].found is True
        # 失败的 provider 以 error_<name> key 记录
        assert "error_bad" in results
        assert results["error_bad"].error == "provider crashed"
        assert results["error_bad"].source == "bad"

    @pytest.mark.asyncio
    async def test_query_hash_empty_providers(self):
        from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService

        service = ThreatIntelService(providers=[])
        results = await service.query_hash("abc123")
        assert results == {}

    @pytest.mark.asyncio
    async def test_query_iocs_delegates_to_providers(self):
        from src.threatscope.analysis.services.threat_intel.base import ThreatIntelResult
        from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService

        provider = MagicMock()
        provider.query_ioc = AsyncMock(
            return_value=ThreatIntelResult(source="p", found=True, data={"ioc": "evil.com"})
        )

        service = ThreatIntelService(providers=[provider])
        results = await service.query_iocs(domains=["evil.com"], ips=None, urls=None)

        assert len(results["domains"]) == 1
        assert results["domains"][0].found is True
        assert results["ips"] == []
        assert results["urls"] == []


class TestBuildService:
    def test_build_service_with_all_enabled(self):
        from unittest.mock import MagicMock

        from src.threatscope.analysis.services.threat_intel.service import build_service

        settings = MagicMock()
        settings.malwarebazaar_enabled = True
        settings.malwarebazaar_url = "https://mb-api.abuse.ch/api/v1/"
        settings.threatfox_enabled = True
        settings.threatfox_url = "https://threatfox-api.abuse.ch/api/v1/"
        settings.urlhaus_enabled = True
        settings.urlhaus_url = "https://urlhaus-api.abuse.ch/v1/"
        settings.virustotal_enabled = True
        settings.virustotal_api_key = "vt-key"
        settings.tix_enabled = True
        settings.tix_app_key = "tix-key"

        service = build_service(settings)
        assert len(service.providers) == 5
        provider_names = {p.name for p in service.providers}
        assert provider_names == {"malwarebazaar", "threatfox", "urlhaus", "virustotal", "tencent_tix"}

    def test_build_service_skips_disabled(self):
        from unittest.mock import MagicMock

        from src.threatscope.analysis.services.threat_intel.service import build_service

        settings = MagicMock()
        settings.malwarebazaar_enabled = True
        settings.malwarebazaar_url = "https://mb-api.abuse.ch/api/v1/"
        settings.threatfox_enabled = False
        settings.urlhaus_enabled = False
        settings.virustotal_enabled = False
        settings.tix_enabled = False

        service = build_service(settings)
        assert len(service.providers) == 1
        assert service.providers[0].name == "malwarebazaar"

    def test_build_service_skips_vt_without_key(self):
        from unittest.mock import MagicMock

        from src.threatscope.analysis.services.threat_intel.service import build_service

        settings = MagicMock()
        settings.malwarebazaar_enabled = False
        settings.threatfox_enabled = False
        settings.urlhaus_enabled = False
        settings.virustotal_enabled = True
        settings.virustotal_api_key = ""  # 没有 key
        settings.tix_enabled = True
        settings.tix_app_key = ""  # 没有 key

        service = build_service(settings)
        assert len(service.providers) == 0
