#!/bin/bash
#
# Runixo Agent 卸载脚本
#

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}请使用 root 用户运行此脚本${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}警告: 这将完全卸载 Runixo Agent${NC}"
read -p "确定要卸载吗? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

echo "停止服务..."
systemctl stop runixo-agent 2>/dev/null || true
systemctl disable runixo-agent 2>/dev/null || true

echo "删除文件..."
rm -f /usr/local/bin/runixo-agent
rm -f /usr/local/bin/runixo
rm -f /etc/systemd/system/runixo-agent.service
rm -rf /etc/runixo

systemctl daemon-reload

echo ""
echo -e "${GREEN}Runixo Agent 已完全卸载${NC}"
echo ""
