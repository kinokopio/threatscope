#!/bin/bash
# ThreatScope 本地开发启动脚本
# 启动 diec 容器并下载 capa 规则

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# 检查 Docker 是否可用
check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker not found. Please install Docker first."
        exit 1
    fi
    
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
}

# 启动 diec 容器
start_diec() {
    local CONTAINER_NAME="threatscope_diec_dev"
    local DIEC_PORT="${DIEC_PORT:-8082}"
    
    # 检查容器是否已运行
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "diec container already running on port ${DIEC_PORT}"
        return 0
    fi
    
    # 检查容器是否存在但已停止
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Starting existing diec container..."
        docker start "$CONTAINER_NAME"
        return 0
    fi
    
    log_info "Building and starting diec container..."
    
    # 构建镜像
    docker build -t threatscope/diec:dev -f "$PROJECT_ROOT/docker/Dockerfile.diec" "$PROJECT_ROOT"
    
    # 运行容器
    docker run -d \
        --name "$CONTAINER_NAME" \
        -p "127.0.0.1:${DIEC_PORT}:8000" \
        -v "$PROJECT_ROOT/data/uploads:/data/uploads:ro" \
        -e DIEC_TIMEOUT=30 \
        --restart unless-stopped \
        threatscope/diec:dev
    
    log_info "diec container started on port ${DIEC_PORT}"
    
    # 等待服务就绪
    log_info "Waiting for diec service to be ready..."
    for i in {1..30}; do
        if curl -s "http://localhost:${DIEC_PORT}/health" > /dev/null 2>&1; then
            log_info "diec service is ready!"
            return 0
        fi
        sleep 1
    done
    
    log_warn "diec service may not be ready yet, but container is running"
}

# 下载 capa 规则
setup_capa_rules() {
    local RULES_DIR="$PROJECT_ROOT/rules/capa"
    local RULES_ZIP="/tmp/capa-rules.zip"
    
    if [ -d "$RULES_DIR" ] && [ "$(ls -A "$RULES_DIR" 2>/dev/null)" ]; then
        log_info "capa rules already exist at $RULES_DIR"
        return 0
    fi
    
    log_info "Downloading capa rules..."
    
    mkdir -p "$RULES_DIR"
    
    # 下载最新规则
    curl -sL "https://github.com/mandiant/capa-rules/releases/latest/download/capa-rules.zip" -o "$RULES_ZIP"
    
    # 解压
    unzip -q -o "$RULES_ZIP" -d "$RULES_DIR"
    rm -f "$RULES_ZIP"
    
    log_info "capa rules downloaded to $RULES_DIR"
}

# 停止 diec 容器
stop_diec() {
    local CONTAINER_NAME="threatscope_diec_dev"
    
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Stopping diec container..."
        docker stop "$CONTAINER_NAME"
        log_info "diec container stopped"
    else
        log_info "diec container is not running"
    fi
}

# 清理 diec 容器
clean_diec() {
    local CONTAINER_NAME="threatscope_diec_dev"
    
    stop_diec
    
    if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        log_info "Removing diec container..."
        docker rm "$CONTAINER_NAME"
        log_info "diec container removed"
    fi
}

# 显示状态
show_status() {
    local CONTAINER_NAME="threatscope_diec_dev"
    local DIEC_PORT="${DIEC_PORT:-8082}"
    local RULES_DIR="$PROJECT_ROOT/rules/capa"
    
    echo ""
    echo "=== ThreatScope Services Status ==="
    echo ""
    
    # diec 状态
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "diec:  ${GREEN}Running${NC} on http://localhost:${DIEC_PORT}"
    else
        echo -e "diec:  ${RED}Stopped${NC}"
    fi
    
    # capa 规则状态
    if [ -d "$RULES_DIR" ] && [ "$(ls -A "$RULES_DIR" 2>/dev/null)" ]; then
        local rule_count=$(find "$RULES_DIR" -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l | tr -d ' ')
        echo -e "capa:  ${GREEN}Rules installed${NC} ($rule_count rules in $RULES_DIR)"
    else
        echo -e "capa:  ${YELLOW}Rules not installed${NC}"
    fi
    
    echo ""
}

# 显示帮助
show_help() {
    echo "ThreatScope 本地开发服务管理"
    echo ""
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start     启动 diec 容器并下载 capa 规则 (默认)"
    echo "  stop      停止 diec 容器"
    echo "  restart   重启 diec 容器"
    echo "  clean     停止并删除 diec 容器"
    echo "  status    显示服务状态"
    echo "  help      显示此帮助"
    echo ""
    echo "Environment variables:"
    echo "  DIEC_PORT   diec 服务端口 (默认: 8082)"
    echo ""
}

# 主函数
main() {
    local cmd="${1:-start}"
    
    case "$cmd" in
        start)
            check_docker
            start_diec
            setup_capa_rules
            show_status
            ;;
        stop)
            stop_diec
            show_status
            ;;
        restart)
            stop_diec
            start_diec
            show_status
            ;;
        clean)
            clean_diec
            show_status
            ;;
        status)
            show_status
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "Unknown command: $cmd"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
