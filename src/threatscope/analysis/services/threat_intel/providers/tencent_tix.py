"""Tencent TIX (xti.qq.com) threat intelligence provider."""

import hashlib
import time

import httpx

from src.threatscope.analysis.services.threat_intel.base import (
    BaseThreatIntelProvider,
    ThreatIntelResult,
)

_TIX_URL = "https://xti.qq.com/api/v3/ti"

_IOC_TYPE_MAP = {
    "ip": ("IPAnalysis", "ip"),
    "ip:port": ("IPAnalysis", "ip"),
    "domain": ("DomainInfo", "domain"),
    "url": ("UrlInfo", "domain"),
}

_URL_THREAT_CLASS = {
    1: "社工欺诈",
    2: "信息诈骗",
    3: "虚假销售",
    4: "恶意文件",
    5: "博彩网站",
    6: "色情网站",
    7: "风险信息",
    8: "违法网站",
    9: "高可疑",
}

_URL_THREAT_TYPE = {
    2: "盗号网站",
    4: "中奖诈骗",
    5: "虚假游戏币充值",
    6: "非法政治",
    7: "欺诈网站",
    8: "刷Q币Q钻",
    10: "欺诈-卡盟",
    13: "非法商品",
    15: "贩卖枪支",
    16: "话费欺诈",
    17: "裸聊",
    18: "仿冒网站-银联举报",
    19: "聊天室",
    20: "成人游戏",
    22: "色情服务",
    23: "微博拉黑",
    24: "下载风险",
    25: "病毒软件",
    26: "病毒软件",
    27: "病毒软件",
    28: "漏洞网站",
    29: "色情网站-扫黄打非",
    30: "可疑盗号",
    31: "仿冒京东",
    32: "仿冒银行",
    33: "仿冒运营商",
    34: "扫黄打非",
    35: "仿冒苹果",
    36: "CNCERT-木马",
    37: "CNCERT-移动病毒",
    38: "CNCERT-钓鱼",
    39: "在线赌博",
    40: "赌博游戏",
    41: "秒赞",
    42: "虚假商品",
    43: "仿冒腾讯网",
    45: "二手交易诈骗",
    46: "充值平台-卡盟",
    47: "虚假兼职",
    49: "赌博投注",
    50: "侵权网站",
    52: "虚假支付",
    53: "虚假兼职",
    60: "仿冒政府",
    62: "虚假广告",
    63: "恶意跳转",
    64: "盗版腾讯视频",
    65: "NBA直播盗版",
    67: "虚假商品",
    68: "空间欺诈",
    70: "清粉",
    76: "含有apk的恶意url",
    79: "虚假投资理财",
    82: "诱导传播-U镜",
    83: "仿冒微信",
    88: "欺诈网站",
    91: "非法政治",
    92: "非法政治",
    93: "非法政治",
    94: "非法政治",
    95: "非法政治",
    96: "非法政治",
    100: "信安博彩",
    101: "信安色情",
    102: "信安事件",
    103: "信安暴力",
    104: "信安违法",
    105: "信安欺诈",
    106: "信安版权",
    107: "信安谣言",
    108: "信安欺诈总",
    110: "恶意挖矿",
    120: "虚假广告推广",
    128: "欺诈网站",
    222: "高考诈骗",
    248: "非法色情",
    250: "游戏盗号",
    255: "tag检测色情",
    257: "非法色情-搜索",
    258: "非法色情",
    259: "非法色情",
    260: "非法色情",
    262: "儿童色情网站",
    263: "加群支付",
    267: "机器学习虚假博彩",
    268: "色情网站",
    269: "机器学习虚假色情",
    270: "虚假支付",
    272: "仿冒公检法_监控",
    280: "私家侦探",
    299: "欺诈投资理财",
    300: "政府同步P2P平台",
    302: "违规口罩销售",
    512: "挂马网站",
    598: "漏洞网站",
    900: "侵权网站",
    1111: "危险网址",
    1112: "危险网址",
    1113: "危险网址",
    2100: "GPS欺诈",
    2257: "虚假信息",
    2300: "虚假信息",
    2305: "骚扰传播",
    2308: "虚假信息",
    2310: "微信诱导分享",
    2501: "色情支付APK",
    2502: "仿冒公检法APK",
    2503: "诱导分享APK",
    2504: "赌博APK",
    2505: "外挂APK",
    2506: "贷款欺诈APP",
    2507: "刷单欺诈APP",
    2508: "理财欺诈APP",
    2509: "赌博APK",
    2510: "杀猪盘APP下载",
    2511: "刷单APP下载",
    2700: "站点QQ发送异常",
    2701: "王者充值",
    2702: "王者礼包",
    2709: "虚假信息",
    2711: "漏洞利用",
    2712: "扫码诱导",
    2713: "虚假信息",
    2902: "西安工商风险网站",
    2903: "西安食药提醒备案",
    2904: "西安食药提示风险",
    3001: "发言侵权",
    8192: "虚假商品",
    8193: "二手车",
    8194: "虚假手表",
    8195: "虚假商品-壮阳",
    8198: "虚假贷款",
    8199: "假信用卡",
    8200: "假银行卡",
    8201: "虚假股票证券交易",
    8250: "虚假外汇交易",
    8251: "可疑外汇交易",
    8258: "外汇交易拦截",
    8260: "高风险小额贷款",
    8268: "杀毒软件威胁下载",
    8269: "股票配资",
    8271: "杀毒软件威胁下载",
    8276: "案情贷款诈骗",
    8278: "仿冒的购物网站",
    8314: "Safari崩溃",
    8315: "色情诱导支付",
    8318: "理财通数字竞猜",
    8321: "仿冒欺诈网站",
    8322: "ETC速通卡仿冒",
    8323: "工商登记诈骗",
    8324: "违规欺诈网站",
    16383: "非法博彩",
    16384: "非法博彩",
    16386: "博彩支付",
    16387: "虚假彩票",
    16388: "腾讯分分彩",
    16389: "非法博彩",
    16394: "高危博彩",
    16396: "博彩诈骗",
    16397: "电竞赌博",
    16398: "博彩诈骗",
    16399: "非法博彩",
    32768: "虚假火车票",
    65536: "虚假视频",
    65537: "虚假视频-沙箱",
    65538: "诱导下载-管家",
    524288: "病毒软件",
    524289: "病毒软件-色播",
    1048578: "木马外挂",
    2097152: "仿冒淘宝",
    4194304: "仿冒腾讯游戏",
    6003101: "非法色情(图像模型识别)",
    8388608: "虚假机票",
    16777216: "金融传销",
    16777300: "微交易微盘",
    33554432: "仿冒网站",
    33554433: "假发票验证平台",
    67108864: "虚假药品",
    67108866: "虚假商品",
    268435456: "淘宝刷钻",
    1001000: "欺诈大类-其他",
}


class TencentTIXProvider(BaseThreatIntelProvider):
    """Queries Tencent TIX for file hash and IOC lookups.

    Supported actions:
    - FileInfo: Query file hash (MD5)
    - IPAnalysis: Query IP address
    - DomainInfo: Query domain name
    - UrlInfo: Query URL

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
        sig_str = "&".join(f"{k}={params[k]}" for k in sorted(params.keys())) + self._app_key
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

    async def query_ioc(self, ioc: str, ioc_type: str) -> ThreatIntelResult:
        if ioc_type not in _IOC_TYPE_MAP:
            return ThreatIntelResult(
                source=self.name,
                found=False,
                data={},
                error=f"Unsupported IOC type: {ioc_type}",
            )

        action, tix_type = _IOC_TYPE_MAP[ioc_type]

        if ioc_type == "ip:port" and ":" in ioc:
            ioc = ioc.split(":")[0]

        try:
            payload = self._build_payload(action, ioc, tix_type)
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
            result_verdict = data.get("result", "")
            confidence = data.get("confidence", 0)

            tags_raw = data.get("tags") or []
            tags = []
            threat_types = []
            for t in tags_raw:
                if isinstance(t, dict):
                    tt = t.get("threat_type", "")
                    if tt:
                        threat_types.append(tt)
                    for stamp in t.get("stamp") or []:
                        if stamp:
                            tags.append(stamp)

            ttps = data.get("ttps") or []

            families = []
            for f in data.get("family") or []:
                if isinstance(f, dict) and f.get("name"):
                    families.append(
                        {
                            "name": f.get("name"),
                            "desc": f.get("desc", "")[:200],
                            "platform": f.get("platform") or [],
                        }
                    )

            campaign = data.get("campaign") or {}
            campaign_name = campaign.get("name", "")

            intelligences = []
            for intel in (data.get("intelligences") or [])[:10]:
                if isinstance(intel, dict):
                    intelligences.append(
                        {
                            "source": intel.get("source", ""),
                            "stamp": intel.get("stamp", ""),
                            "time": intel.get("time", ""),
                        }
                    )

            result_data = {
                "ioc_type": ioc_type,
                "ioc_value": ioc,
                "verdict": result_verdict,
                "threat_level": threat_level,
                "confidence": confidence,
                "threat_types": threat_types,
                "tags": tags,
                "ttps": ttps,
                "families": families,
                "intelligences": intelligences,
                "first_seen": data.get("first_seen", ""),
                "last_seen": data.get("last_seen", ""),
            }

            if campaign_name:
                result_data["campaign"] = {
                    "name": campaign_name,
                    "alias": campaign.get("alias") or [],
                    "source_area": campaign.get("source_area", ""),
                    "industry": campaign.get("industry") or [],
                }

            if ioc_type in ("ip", "ip:port"):
                basic = data.get("basic") or {}
                if basic:
                    result_data["geo"] = {
                        "country": basic.get("country", ""),
                        "province": basic.get("province", ""),
                        "city": basic.get("city", ""),
                        "isp": basic.get("isp", ""),
                        "asn": basic.get("asn", ""),
                    }
                result_data["profile"] = data.get("profile") or []

                ctx = data.get("context") or {}
                related = []
                for md5_info in (ctx.get("black_md5_visit_ip") or [])[:5]:
                    if isinstance(md5_info, dict) and md5_info.get("hash"):
                        related.append(
                            {
                                "hash": md5_info.get("hash"),
                                "virus_name": md5_info.get("virus_name", ""),
                                "relation": "visited_ip",
                            }
                        )
                for md5_info in (ctx.get("black_md5_download_from_ip") or [])[:5]:
                    if isinstance(md5_info, dict) and md5_info.get("hash"):
                        related.append(
                            {
                                "hash": md5_info.get("hash"),
                                "virus_name": md5_info.get("virus_name", ""),
                                "relation": "downloaded_from_ip",
                            }
                        )
                if related:
                    result_data["related_samples"] = related

                hist_domains = []
                for hd in (ctx.get("historical_domain") or [])[:10]:
                    if isinstance(hd, dict) and hd.get("domain"):
                        hist_domains.append(hd.get("domain"))
                if hist_domains:
                    result_data["historical_domains"] = hist_domains

            elif ioc_type == "domain":
                basic = data.get("basic") or {}
                if basic.get("registrant_organization") or basic.get("create_time"):
                    result_data["registration"] = {
                        "registrant": basic.get("registrant_organization", ""),
                        "registrar": basic.get("registrar_name", ""),
                        "created": basic.get("create_time", ""),
                        "expires": basic.get("expire_time", ""),
                        "updated": basic.get("update_time", ""),
                    }

                rank = data.get("rank") or {}
                tranco = rank.get("tranco_rank", 0)
                umbrella = rank.get("umbrella_rank", 0)
                if tranco > 0 or umbrella > 0:
                    result_data["rank"] = {"tranco": tranco, "umbrella": umbrella}

                icp = data.get("icp") or {}
                if icp.get("icp_license") or icp.get("subject_name"):
                    result_data["icp"] = {
                        "license": icp.get("icp_license", ""),
                        "subject": icp.get("subject_name", ""),
                        "web_name": icp.get("web_name", ""),
                    }

                ctx = data.get("context") or {}

                articles = []
                for art in (ctx.get("articles") or [])[:3]:
                    if isinstance(art, dict) and art.get("desc"):
                        articles.append(
                            {
                                "desc": art.get("desc", "")[:300],
                                "time": art.get("time", ""),
                                "usefor": art.get("usefor", ""),
                            }
                        )
                if articles:
                    result_data["threat_articles"] = articles

                related = []
                for md5_info in (ctx.get("black_md5_visit_domain") or [])[:5]:
                    if isinstance(md5_info, dict) and md5_info.get("hash"):
                        related.append(
                            {
                                "hash": md5_info.get("hash"),
                                "virus_name": md5_info.get("virus_name", ""),
                                "relation": "visited_domain",
                            }
                        )
                for md5_info in (ctx.get("black_md5_download_from_domain") or [])[:5]:
                    if isinstance(md5_info, dict) and md5_info.get("hash"):
                        related.append(
                            {
                                "hash": md5_info.get("hash"),
                                "virus_name": md5_info.get("virus_name", ""),
                                "relation": "downloaded_from_domain",
                            }
                        )
                if related:
                    result_data["related_samples"] = related

                malicious_urls = []
                for url_info in (ctx.get("black_url_of_domain") or [])[:10]:
                    if isinstance(url_info, dict) and url_info.get("url"):
                        malicious_urls.append(url_info.get("url"))
                if malicious_urls:
                    result_data["malicious_urls"] = malicious_urls

            elif ioc_type == "url":
                threat_type_code = data.get("threat_type", 0)
                threat_class_code = data.get("threat_class", 0)
                url_type = data.get("url_type", 0)
                url_threat_level = data.get("threat_level", "")

                threat_class_name = _URL_THREAT_CLASS.get(threat_class_code, "")
                threat_type_name = _URL_THREAT_TYPE.get(threat_type_code, "")

                result_data = {
                    "ioc_type": ioc_type,
                    "ioc_value": ioc,
                    "verdict": result_verdict,
                    "confidence": confidence,
                    "threat_class": threat_class_name,
                    "threat_class_code": threat_class_code,
                    "threat_type": threat_type_name,
                    "threat_type_code": threat_type_code,
                    "url_type": url_type,
                    "scope_level": url_threat_level,
                }

                is_malicious = result_verdict == "black" or url_type in (2, 5, 6)

                return ThreatIntelResult(
                    source=self.name,
                    found=is_malicious,
                    data=result_data,
                )

            is_malicious = result_verdict == "black" or threat_level >= 2

            return ThreatIntelResult(
                source=self.name,
                found=is_malicious,
                data=result_data,
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
