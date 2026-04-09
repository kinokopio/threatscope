"""Tencent TIX (xti.qq.com) threat intelligence provider."""

import hashlib
import time

import httpx

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)

_TIX_URL = "https://xti.qq.com/api/v3/ti"


class TencentTIXProvider(BaseThreatIntelProvider):
    """Queries Tencent TIX for file hash lookups via FileInfo action.

    Authentication: HMAC-like SHA256 signature.
    All request params (sorted) are concatenated as "k=v&..." with the appkey
    appended at the end, then SHA256-hashed into c_signature. The appkey itself
    is NOT included in the request body — only c_appid and c_signature are sent.
    """

    name = "tencent_tix"

    def __init__(self, app_id: str, app_key: str, timeout: int = 30):
        self._app_id = app_id
        self._app_key = app_key
        self.timeout = timeout

    def _build_payload(self, action: str, key: str, key_type: str) -> dict:
        """Build signed request payload for TIX API."""
        params = {
            "c_version": "3.0",
            "c_action": action,
            "c_nonce": "118a6",
            "c_timestamp": int(time.time()),
            "key": key,
            "type": key_type,
            "c_appid": self._app_id,
            "option": 0,
        }
        # Signature: sorted "k=v" pairs joined by "&", appkey appended, then SHA256
        sig_str = "&".join(
            f"{k}={params[k]}" for k in sorted(params.keys())
        ) + self._app_key
        params["c_signature"] = hashlib.sha256(sig_str.encode("utf-8")).hexdigest()
        return params

    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        """Query TIX FileInfo by MD5 hash.

        TIX only accepts MD5 (32 hex chars). Callers should pass the MD5 field
        from their hashes dict. Non-MD5 hashes are sent as-is; TIX will return
        a non-zero return_code which is surfaced as an error.

        Returns found=True when return_code==0 and risk_level > 0.
        """
        try:
            payload = self._build_payload("FileInfo", hash_value, "md5")
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(_TIX_URL, json=payload)
                response.raise_for_status()
                data = response.json()

            if data.get("return_code") != 0:
                return ThreatIntelResult(
                    source=self.name,
                    found=False,
                    data={},
                    error=data.get("return_msg", "unknown error"),
                )

            threat_level = data.get("threat_level", 0)
            basicinfo = data.get("basicinfo", {})
            tags = [t.get("tag", "") for t in (data.get("tags") or []) if t.get("tag")]

            # Extract ATT&CK TTPs
            ttps = []
            for ttp in data.get("ttps") or []:
                if isinstance(ttp, dict) and ttp.get("ttp_id"):
                    ttps.append({"id": ttp.get("ttp_id"), "name": ttp.get("ttp_name", "")})

            # Extract threat groups
            groups = [g.get("name") for g in (data.get("groups") or []) if g.get("name")]

            return ThreatIntelResult(
                source=self.name,
                found=threat_level > 0,
                data={
                    "threat_level": threat_level,
                    "result": data.get("result", ""),
                    "threat_type": data.get("threat_type") or [],
                    "tags": tags,
                    "file_name": basicinfo.get("file_name"),
                    "file_type": basicinfo.get("file_type"),
                    "file_size": basicinfo.get("file_size"),
                    "submit_time": basicinfo.get("submit_time"),
                    "intelligences": data.get("intelligences") or [],
                    "groups": groups,
                    "ttps": ttps,
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
