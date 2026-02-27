# ThreatScope 部署指南

## 本次更新内容

### 1. 分步显示功能
- 每个分析步骤完成后立即保存到数据库
- 前端实时显示进度，不再等待全部完成

### 2. 动态分析超时修复
- 超时时间从 300 秒改为 30 秒
- 使用容器内 `timeout` 命令确保 QEMU 被正确终止
- 修复了超时后容器未清理的问题

### 3. 修改的文件
```
api/rest.py                 - 分步保存逻辑
core/config.py              - 添加 dynamic_analysis_timeout 配置
core/coordinator.py         - 使用新的超时配置
core/database.py            - 添加 merge_stage_1_4_result 方法
config.yaml                 - 添加 dynamic_analysis_timeout: 30
tools/dynamic/emulator.py   - 修复超时和清理逻辑
```

## 服务器部署步骤

### 1. 清理卡住的进程（如果有）

```bash
# 查看残留的 threatscope 容器
docker ps -a | grep threatscope

# 强制清理容器
docker ps -a | grep threatscope | awk '{print $1}' | xargs -r docker kill
docker ps -a | grep threatscope | awk '{print $1}' | xargs -r docker rm -f

# 查看 QEMU 进程
ps aux | grep qemu

# 如果有残留的 QEMU 进程，强制杀死
sudo pkill -9 -f "qemu.*strace"
```

### 2. 更新代码

```bash
cd /home/ubuntu/threatscope

# 方法 A: 使用 git pull（如果已配置远程仓库）
git pull origin main

# 方法 B: 手动复制修改的文件
# 从本地机器 scp 文件到服务器
```

### 3. 重启服务

```bash
# 停止现有服务
sudo systemctl stop threatscope

# 或者手动杀死进程
pkill -f "uvicorn api.rest:app"
pkill -f "npm run dev"

# 重新启动后端
cd /home/ubuntu/threatscope
source .venv/bin/activate
nohup uvicorn api.rest:app --host 0.0.0.0 --port 8000 > /tmp/backend.log 2>&1 &

# 重新启动前端
cd /home/ubuntu/threatscope/frontend
nohup npm run dev -- --host 0.0.0.0 > /tmp/frontend.log 2>&1 &
```

### 4. 验证

```bash
# 检查服务状态
curl http://localhost:8000/health

# 查看后端日志
tail -f /tmp/backend.log

# 测试分析
curl -X POST http://localhost:8000/analyze \
  -F "file=@/path/to/test/binary" \
  -F "enable_dynamic=true"
```

## 关键配置

### config.yaml
```yaml
analysis:
  default_timeout: 300
  dynamic_analysis_timeout: 30  # 动态分析超时（秒）
  enable_dynamic_analysis: true
  enable_ghidra_analysis: true
  yara_rules_path: "rules/yara"
```

## 故障排除

### 动态分析卡住
1. 检查 Docker 容器：`docker ps -a | grep threatscope`
2. 检查 QEMU 进程：`ps aux | grep qemu`
3. 强制清理：见上方清理命令

### 前端不显示进度
1. 检查后端日志中的 "Saved xxx to database" 消息
2. 确认数据库文件权限正确
3. 检查前端轮询是否正常（Network tab）

### YARA 规则加载慢
确保使用预编译规则：
```bash
ls -la rules/yara/compiled_rules.yarc
```
