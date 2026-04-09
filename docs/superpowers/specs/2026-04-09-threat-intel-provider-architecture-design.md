# 威胁情报模块重构设计文档

**日期：** 2026-04-09  
**状态：** 待实现  
**范围：** `src/threatscope/analysis/services/threat_intel/`

---

## 背景

现有 `threat_intel.py` 是单文件大类，支持 MalwareBazaar、ThreatFox、URLhaus 三个情报源。每新增一个源需要在同一文件里堆新方法，`__init__` 参数不断增长，`query_hash` 里手动维护 gather 任务列表。本次重构引入 Provider 架构，同时新增腾讯 TIX 和 VirusTotal 两个情报源。

---

## 目标

- 将 `threat_intel.py` 拆成 Provider 子包，每个情报源独立文件
- 所有 Provider 实现统一抽象接口
- 新增 VirusTotal、腾讯 TIX 两个 hash 查询 Provider
- 对上层（`coordinator.py`）的调用接口保持零破坏
- 新增配置项走现有 `ThreatIntelSettings`，通过 `.env` 管理

---

## 目录结构

```
src/threatscope/analysis/services/threat_intel/
├── __init__.py           # 重导出 ThreatIntelService，保持 import 路径不变
├── base.py               # BaseThreatIntelProvider ABC + ThreatIntelResult
├── service.py            # ThreatIntelService（聚合器）
└── providers/
    ├── __init__.py
    ├── malwarebazaar.py  # 从现有 threat_intel.py 迁移
    ├── threatfox.py      # 从现有 threat_intel.py 迁移
    ├── urlhaus.py        # 从现有 threat_intel.py 迁移
    ├── virustotal.py     # 新增
    └── tencent_tix.py    # 新增
```

旧文件 `src/threatscope/analysis/services/threat_intel.py` 删除，替换为上述子包。

---

## 抽象接口：`base.py`

```python
class ThreatIntelResult:
    source: str
    found: bool
    data: dict[str, Any]
    error: str | None = None

class BaseThreatIntelProvider(ABC):
    name: str  # 标识符，如 "virustotal"、"tencent_tix"

    @abstractmethod
    async def query_hash(self, hash_value: str) -> ThreatIntelResult:
        """查询文件 hash（SHA256 优先，兼容 MD5/SHA1）"""
        ...

    async def query_ioc(self, ioc: str, ioc_type: str) -> ThreatIntelResult:
        """查询 IOC（域名/IP/URL），默认不支持，子类可覆盖"""
        return ThreatIntelResult(source=self.name, found=False, data={})
```

`query_hash` 是唯一强制实现的方法。`query_ioc` 默认返回 `found=False`，URLhaus 等有 IOC 查询能力的 Provider 覆盖此方法。

---

## 聚合器：`service.py`

```python
class ThreatIntelService:
    def __init__(self, providers: list[BaseThreatIntelProvider]):
        self.providers = providers

    async def query_hash(self, hash_value: str) -> dict[str, ThreatIntelResult]:
        results = await asyncio.gather(
            *[p.query_hash(hash_value) for p in self.providers],
            return_exceptions=True,
        )
        output = {}
        for result in results:
            if isinstance(result, ThreatIntelResult):
                output[result.source] = result
            elif isinstance(result, Exception):
                # 单个 provider 失败不影响其他源
                output[f"error_{id(result)}"] = ThreatIntelResult(
                    source="unknown", found=False, data={}, error=str(result)
                )
        return output

    async def query_iocs(self, domains, ips, urls) -> dict[str, list[ThreatIntelResult]]:
        # 逻辑不变，委托给支持 query_ioc 的 provider
        ...
```

---

## Provider 实现要点

### 现有三个源（迁移，逻辑不变）

| Provider | 文件 | 认证 | hash 接口 |
|---|---|---|---|
| MalwareBazaar | `malwarebazaar.py` | 无 | POST form-data |
| ThreatFox | `threatfox.py` | 无 | POST JSON |
| URLhaus | `urlhaus.py` | 无 | POST form-data；覆盖 `query_ioc` |

逻辑从现有 `threat_intel.py` 原样迁入对应文件，只做类包装，不改业务逻辑。

### VirusTotal（新增）

- **接口：** `GET https://www.virustotal.com/api/v3/files/{hash}`
- **认证：** Header `x-apikey: {api_key}`
- **提取字段：**
  - `last_analysis_stats`：malicious / suspicious / undetected / harmless 计数
  - `meaningful_name`：引擎识别的文件名
  - `popular_threat_classification`：威胁分类标签
- **found 判定：** HTTP 200 且 `last_analysis_stats.malicious > 0`

### 腾讯 TIX（新增）

- **接口：** `POST https://xti.qq.com/api/v3/ti`
- **认证：** Body JSON 中 `c_appkey` 字段
- **使用 `FileReport` action**，通过 `md5` 参数查询（需传 MD5，故 coordinator 传入 hashes 中的 `md5` 字段）
- **提取字段：**
  - `data.summary.risk_level`：0=无风险，>0 为威胁
  - `data.vdc_infos.virusname`：引擎识别的病毒名
  - `data.tag_info`：威胁标签
- **found 判定：** `return_code == 0` 且 `risk_level > 0`

---

## 配置变更：`ThreatIntelSettings`

在 `config.py` 的 `ThreatIntelSettings` 中追加：

```python
virustotal_enabled: bool = Field(default=False)
virustotal_api_key: str = Field(default="")

tix_enabled: bool = Field(default=False)
tix_app_key: str = Field(default="")
```

`.env` 中配置：

```
THREATSCOPE_THREAT_INTEL_VIRUSTOTAL_ENABLED=true
THREATSCOPE_THREAT_INTEL_VIRUSTOTAL_API_KEY=xxx

THREATSCOPE_THREAT_INTEL_TIX_ENABLED=true
THREATSCOPE_THREAT_INTEL_TIX_APP_KEY=xxx
```

---

## Provider 注册与构建

在 `ThreatIntelService` 提供一个工厂方法，或在 `__init__.py` 中提供 `build_service(settings)` 函数，根据 settings 中各 provider 的 `enabled` 开关组装 provider 列表：

```python
def build_service(settings: ThreatIntelSettings) -> ThreatIntelService:
    providers = []
    if settings.malwarebazaar_enabled:
        providers.append(MalwareBazaarProvider(settings.malwarebazaar_url))
    if settings.threatfox_enabled:
        providers.append(ThreatFoxProvider(settings.threatfox_url))
    if settings.urlhaus_enabled:
        providers.append(URLhausProvider(settings.urlhaus_url))
    if settings.virustotal_enabled and settings.virustotal_api_key:
        providers.append(VirusTotalProvider(settings.virustotal_api_key))
    if settings.tix_enabled and settings.tix_app_key:
        providers.append(TencentTIXProvider(settings.tix_app_key))
    return ThreatIntelService(providers)
```

`coordinator.py` 中将 `self.threat_intel = ThreatIntelService()` 改为 `self.threat_intel = build_service(self.settings.threat_intel)`。

---

## 对外接口兼容性

| 调用方 | 变化 |
|---|---|
| `coordinator.py` 的 import | 不变：`from ...services.threat_intel import ThreatIntelService` |
| `coordinator.py` 的实例化 | 改为调用 `build_service(settings.threat_intel)` |
| `query_hash` / `query_iocs` 方法签名 | 不变 |
| 返回值结构 | 不变（`dict[str, ThreatIntelResult]`） |

---

## 错误处理

- 单个 Provider 失败（网络超时、认证错误）不影响其他 Provider 的结果
- `asyncio.gather(..., return_exceptions=True)` 捕获异常，失败的 Provider 在结果中以 `error` 字段体现
- API Key 未配置时，对应 Provider 不加入列表（不会发起请求）

---

## 不在本次范围内

- IOC 查询不新增 VT/TIX 支持（仅做 hash）
- 速率限制 / 请求队列（VT 免费版有 4 req/min 限制，后续可加）
- 结果缓存
