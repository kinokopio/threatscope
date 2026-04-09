"""Tencent TIX (xti.qq.com) threat intelligence provider."""

import httpx

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)

_TIX_URL = "https://xti.qq.com/api/v3/ti"


class TencentTIXProvider(BaseThreatIntelProvider):
    """Queries Tencent TIX for file hash lookups via FileReport action.

    Authentication: c_appkey field in JSON request body (not a header).
    API docs: https://tix.qq.com/apinterface/overview
    """

    name = "tencent_tix"

    def __init__(self, app_key: str, timeout: int = 30):
        """Args:
        app_key: TIX AppKey obtained from tix@tencent.com.
        timeout: HTTP request timeout in seconds.
        """
        self._app_key = app_key
        self.timeout = timeout

    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        """Query TIX FileReport by MD5 hash.

        TIX FileReport only accepts MD5 (not SHA256/SHA1). If the caller
        passes a non-MD5 hash (len != 32), the request is still sent;
        TIX will return return_code != 0 which is handled as an error.

        Returns found=True when return_code==0 and risk_level > 0.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    _TIX_URL,
                    params={"md5": hash_value},
                    json={
                        "c_version": "3.0",
                        "c_action": "FileReport",
                        "c_appkey": self._app_key,
                    },
                )
                response.raise_for_status()
                data = response.json()

                if data.get("return_code") != 0:
                    return ThreatIntelResult(
                        source=self.name,
                        found=False,
                        data={},
                        error=data.get("return_msg", "unknown error"),
                    )

                report = data.get("data", {})
                summary = report.get("summary", {})
                vdc = report.get("vdc_infos", {})
                risk_level = summary.get("risk_level", 0)

                return ThreatIntelResult(
                    source=self.name,
                    found=risk_level > 0,
                    data={
                        "risk_level": risk_level,
                        "virusname": vdc.get("virusname", ""),
                        "file_type": summary.get("file_type"),
                        "tag_info": report.get("tag_info"),
                        "task_id": summary.get("taskid"),
                    },
                )
        except httpx.HTTPStatusError as e:
            return ThreatIntelResult(
                source=self.name,
                found=False,
                data={},
                error=f"HTTP {e.response.status_code}: {e.response.text[:200]}",
            )
        except Exception as e:
            return ThreatIntelResult(source=self.name, found=False, data={}, error=str(e))
