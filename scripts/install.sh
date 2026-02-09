#!/bin/bash
#
# Runixo Agent 一键安装脚本
#
# 使用方法:
#   curl -fsSL https://raw.githubusercontent.com/Zhang142857/runixo/main/scripts/install.sh | sudo bash
#
# 环境变量:
#   RUNIXO_TOKEN    - 预设认证令牌
#   RUNIXO_PORT     - 监听端口 (默认: 9527)
#

set -e

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# 配置
GITHUB_REPO="Zhang142857/runixo"
BINARY_NAME="runixo-agent"
CONFIG_DIR="/etc/runixo"
CONFIG_FILE="${CONFIG_DIR}/agent.yaml"
DATA_DIR="/var/lib/runixo"
SERVICE_FILE="/etc/systemd/system/runixo-agent.service"
INSTALL_DIR="/usr/local/bin"
PORT="${RUNIXO_PORT:-9527}"
API_PORT=$((PORT + 1))

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[✓]${NC} $1"; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
log_error()   { echo -e "${RED}[✗]${NC} $1"; }
log_step()    { echo -e "${CYAN}[STEP]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用 root 用户运行: curl -fsSL ... | sudo bash"
        exit 1
    fi
}

get_public_ip() {
    for svc in ifconfig.me ipinfo.io/ip icanhazip.com api.ipify.org; do
        local ip=$(curl -fsSL --connect-timeout 3 "$svc" 2>/dev/null | tr -d '\n\r ')
        if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "$ip"; return
        fi
    done
    echo "无法获取"
}

get_local_ip() {
    hostname -I 2>/dev/null | awk '{print $1}' || ip route get 1 2>/dev/null | awk '{print $7; exit}' || echo "无法获取"
}

# 读取已有 token（升级时保留）
get_existing_token() {
    if [ -f "$CONFIG_FILE" ]; then
        grep 'token:' "$CONFIG_FILE" 2>/dev/null | head -1 | sed 's/.*token: *"\?\([^"]*\)"\?/\1/' | tr -d ' '
    fi
}

generate_token() {
    if [ -n "${RUNIXO_TOKEN}" ]; then
        echo "${RUNIXO_TOKEN}"
    elif command -v openssl &>/dev/null; then
        openssl rand -hex 32
    else
        head -c 32 /dev/urandom | xxd -p | tr -d '\n'
    fi
}

check_dependencies() {
    log_step "检查依赖..."
    local missing=()
    for cmd in curl; do
        command -v $cmd &>/dev/null || missing+=($cmd)
    done
    if [ ${#missing[@]} -eq 0 ]; then
        log_success "依赖检查通过"
        return
    fi
    log_info "安装缺失依赖: ${missing[*]}"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq && apt-get install -y -qq "${missing[@]}"
    elif command -v yum &>/dev/null; then
        yum install -y -q "${missing[@]}"
    elif command -v dnf &>/dev/null; then
        dnf install -y -q "${missing[@]}"
    elif command -v apk &>/dev/null; then
        apk add --no-cache "${missing[@]}"
    else
        log_error "无法自动安装依赖，请手动安装: ${missing[*]}"
        exit 1
    fi
    log_success "依赖安装完成"
}

stop_and_cleanup() {
    log_step "清理旧版本..."
    # 停止所有可能的旧服务
    for svc in runixo-agent serverhub-agent; do
        systemctl stop "$svc" 2>/dev/null || true
        systemctl disable "$svc" 2>/dev/null || true
    done
    pkill -9 -f runixo-agent 2>/dev/null || true
    pkill -9 -f serverhub-agent 2>/dev/null || true
    # 清理旧版二进制（serverhub 时代的）
    rm -f /usr/local/bin/serverhub-agent /usr/local/bin/serverhub
    rm -f /etc/systemd/system/serverhub-agent.service
    rm -rf /etc/serverhub
    systemctl daemon-reload 2>/dev/null || true
    log_success "旧版本已清理"
}

free_port() {
    log_step "检查端口 ${PORT}..."
    local pid=$(lsof -ti:${PORT} 2>/dev/null | head -1)
    if [ -n "$pid" ]; then
        log_warn "端口 ${PORT} 被 PID ${pid} 占用，正在释放..."
        kill -9 "$pid" 2>/dev/null || true
        sleep 1
    fi
    # 同时检查 API 端口
    local api_pid=$(lsof -ti:${API_PORT} 2>/dev/null | head -1)
    if [ -n "$api_pid" ]; then
        kill -9 "$api_pid" 2>/dev/null || true
        sleep 1
    fi
    log_success "端口就绪"
}

configure_firewall() {
    # UFW
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow ${PORT}/tcp >/dev/null 2>&1
        ufw allow ${API_PORT}/tcp >/dev/null 2>&1
    fi
    # firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld 2>/dev/null; then
        firewall-cmd --permanent --add-port=${PORT}/tcp >/dev/null 2>&1
        firewall-cmd --permanent --add-port=${API_PORT}/tcp >/dev/null 2>&1
        firewall-cmd --reload >/dev/null 2>&1
    fi
    # iptables
    if command -v iptables &>/dev/null; then
        iptables -C INPUT -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport ${PORT} -j ACCEPT 2>/dev/null || true
        iptables -C INPUT -p tcp --dport ${API_PORT} -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p tcp --dport ${API_PORT} -j ACCEPT 2>/dev/null || true
    fi
}

download_binary() {
    log_step "下载 Runixo Agent..."
    
    # 检测架构
    local arch=$(uname -m)
    case "$arch" in
        x86_64|amd64)  arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        armv7l)        arch="arm" ;;
        *)
            log_error "不支持的架构: $arch"
            exit 1
            ;;
    esac
    
    local filename="runixo-agent-linux-${arch}"
    local url="https://github.com/${GITHUB_REPO}/releases/download/latest/${filename}"
    
    log_info "架构: ${arch}"
    
    local tmp=$(mktemp)
    if ! curl -fL --progress-bar -o "$tmp" "$url" 2>&1; then
        rm -f "$tmp"
        log_error "下载失败: $url"
        exit 1
    fi
    
    mv "$tmp" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    local ver=$(${INSTALL_DIR}/${BINARY_NAME} --version 2>&1 | head -1)
    log_success "Agent 已安装: ${ver}"
}

create_config() {
    local token=$1
    mkdir -p "${CONFIG_DIR}" "${DATA_DIR}"
    cat > "${CONFIG_FILE}" << EOF
server:
  host: "0.0.0.0"
  port: ${PORT}
  api_port: ${API_PORT}
  tls:
    enabled: true

auth:
  token: "${token}"

metrics:
  interval: 2

log:
  level: "info"

data:
  dir: "${DATA_DIR}"

plugins:
  dir: "${DATA_DIR}/plugins"

update:
  auto: false
  channel: "stable"
  interval: 3600
EOF
    chmod 600 "${CONFIG_FILE}"
    log_success "配置文件已创建"
}

create_service() {
    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=Runixo Agent
After=network.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --config ${CONFIG_FILE}
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    log_success "systemd 服务已创建"
}

create_cli() {
    cat > "${INSTALL_DIR}/runixo" << 'EOFCLI'
#!/bin/bash
CONFIG="/etc/runixo/agent.yaml"
SVC="runixo-agent"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

get_val() { grep "$1" "$CONFIG" 2>/dev/null | head -1 | sed "s/.*$1: *\"\?\([^\"]*\)\"\?.*/\1/" | tr -d ' '; }
get_public_ip() { curl -fsSL --connect-timeout 3 ifconfig.me 2>/dev/null || echo "无法获取"; }
get_local_ip() { hostname -I 2>/dev/null | awk '{print $1}' || echo "无法获取"; }

case "${1:-info}" in
  status)  systemctl status $SVC --no-pager ;;
  start)   systemctl start $SVC && echo -e "${GREEN}已启动${NC}" ;;
  stop)    systemctl stop $SVC && echo -e "${YELLOW}已停止${NC}" ;;
  restart) systemctl restart $SVC && sleep 1 && systemctl is-active --quiet $SVC && echo -e "${GREEN}已重启${NC}" || echo -e "${RED}重启失败${NC}" ;;
  logs)    journalctl -u $SVC -f ;;
  info)
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo -e "  ${CYAN}公网地址:${NC}  ${BOLD}$(get_public_ip)${NC}"
    echo -e "  ${CYAN}内网地址:${NC}  $(get_local_ip)"
    echo -e "  ${CYAN}端口:${NC}      ${BOLD}$(get_val port | head -1)${NC}"
    echo -e "  ${CYAN}Token:${NC}     ${GREEN}$(get_val token)${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════${NC}"
    echo "" ;;
  token)      echo -e "Token: ${GREEN}$(get_val token)${NC}" ;;
  token:reset)
    NEW=$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p | tr -d '\n')
    OLD=$(get_val token)
    sed -i "s/$OLD/$NEW/" "$CONFIG"
    systemctl restart $SVC
    echo -e "新 Token: ${GREEN}${NEW}${NC}" ;;
  uninstall)
    read -p "确定卸载? [y/N] " -n 1 -r; echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 0
    systemctl stop $SVC 2>/dev/null; systemctl disable $SVC 2>/dev/null
    rm -f /usr/local/bin/runixo-agent /usr/local/bin/runixo /etc/systemd/system/runixo-agent.service
    rm -rf /etc/runixo; systemctl daemon-reload
    echo -e "${GREEN}已卸载${NC}" ;;
  help|*)
    echo "用法: runixo <命令>"
    echo "  info / status / start / stop / restart / logs"
    echo "  token / token:reset / uninstall / help" ;;
esac
EOFCLI
    chmod +x "${INSTALL_DIR}/runixo"
    log_success "runixo 管理命令已安装"
}

start_service() {
    log_step "启动服务..."
    systemctl enable runixo-agent >/dev/null 2>&1
    systemctl start runixo-agent
    local i=0
    while [ $i -lt 5 ]; do
        systemctl is-active --quiet runixo-agent && break
        sleep 1; i=$((i+1))
    done
    if systemctl is-active --quiet runixo-agent; then
        log_success "服务已启动"
    else
        log_error "服务启动失败，查看日志: journalctl -u runixo-agent -n 20"
        journalctl -u runixo-agent -n 10 --no-pager 2>/dev/null
        exit 1
    fi
}

show_result() {
    local token=$1
    local pub_ip=$(get_public_ip)
    local lan_ip=$(get_local_ip)
    
    # 等待证书生成
    local cert_file="${DATA_DIR}/tls/cert.pem"
    local i=0
    while [ $i -lt 10 ]; do
        if [ -f "$cert_file" ]; then
            break
        fi
        sleep 1
        i=$((i+1))
    done
    
    echo ""
    echo -e "${BOLD}╔═══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║          ${GREEN}✓ Runixo Agent 安装成功${NC}${BOLD}                        ║${NC}"
    echo -e "${BOLD}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║${NC}                                                           ${BOLD}║${NC}"
    echo -e "${BOLD}║${NC}  ${CYAN}公网 IP:${NC}  ${BOLD}${pub_ip}${NC}"
    echo -e "${BOLD}║${NC}  ${CYAN}内网 IP:${NC}  ${lan_ip}"
    echo -e "${BOLD}║${NC}  ${CYAN}端  口:${NC}  ${BOLD}${PORT}${NC}"
    echo -e "${BOLD}║${NC}  ${CYAN}Token:${NC}   ${GREEN}${token}${NC}"
    echo -e "${BOLD}║${NC}                                                           ${BOLD}║${NC}"
    echo -e "${BOLD}╠═══════════════════════════════════════════════════════════╣${NC}"
    echo -e "${BOLD}║${NC}  管理命令: ${CYAN}sudo runixo info${NC}                                ${BOLD}║${NC}"
    echo -e "${BOLD}╚═══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # 输出证书内容（供客户端解析）
    if [ -f "$cert_file" ]; then
        echo "-----BEGIN RUNIXO CERTIFICATE-----"
        cat "$cert_file"
        echo "-----END RUNIXO CERTIFICATE-----"
    fi
    
    # 输出纯文本 Token（供客户端 SSH 安装解析）
    echo "Token: ${token}"
}

main() {
    echo ""
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo -e "${BOLD}     Runixo Agent 一键安装脚本${NC}"
    echo -e "${BOLD}══════════════════════════════════════════${NC}"
    echo ""

    check_root

    log_info "系统: $(uname -s) $(uname -m) | $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo 'Unknown')"
    echo ""

    # 保留已有 token
    local existing_token=$(get_existing_token)

    check_dependencies
    stop_and_cleanup
    free_port
    configure_firewall
    download_binary

    local token="${existing_token}"
    if [ -z "$token" ] || [ "$token" = '""' ] || [ "$token" = "''" ]; then
        token=$(generate_token)
    fi

    create_config "$token"
    create_service
    create_cli
    start_service
    show_result "$token"
}

main "$@"
