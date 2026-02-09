# Runixo Agent 安装脚本

## 一键安装

```bash
curl -fsSL https://cdn.jsdelivr.net/gh/Zhang142857/runixo@main/scripts/install.sh | sudo bash
```

安装完成后会显示服务器连接信息（公网IP、端口、认证令牌），可直接在客户端使用。

### 自定义安装

```bash
# 指定端口
RUNIXO_PORT=8080 curl -fsSL https://cdn.jsdelivr.net/gh/Zhang142857/runixo@main/scripts/install.sh | sudo bash

# 预设令牌
RUNIXO_TOKEN=your-secret-token curl -fsSL https://cdn.jsdelivr.net/gh/Zhang142857/runixo@main/scripts/install.sh | sudo bash
```

## runixo 管理命令

安装后可使用 `runixo` 命令管理 Agent：

```bash
runixo info          # 查看连接信息（公网IP、端口、令牌）
runixo status        # 查看服务状态
runixo start         # 启动服务
runixo stop          # 停止服务
runixo restart       # 重启服务
runixo logs          # 查看日志
runixo token         # 显示当前令牌
runixo token:reset   # 重置认证令牌
runixo port <端口>   # 修改监听端口
runixo config        # 编辑配置文件
runixo uninstall     # 卸载 Agent
runixo help          # 查看帮助
```

## 卸载

```bash
# 方式一：使用 runixo 命令
sudo runixo uninstall

# 方式二：使用卸载脚本
curl -fsSL https://cdn.jsdelivr.net/gh/Zhang142857/runixo@main/scripts/uninstall.sh | sudo bash
```

## 支持的平台

| 操作系统 | 架构 |
|----------|------|
| Linux | x86_64 (amd64) |
| Linux | ARM64 (aarch64) |
| Linux | ARMv7 |
| macOS | x86_64 / ARM64 |

## 配置文件

位于 `/etc/runixo/agent.yaml`，可通过 `runixo config` 编辑。

## 故障排除

```bash
# 查看服务状态
runixo status

# 查看日志
runixo logs

# 手动运行查看错误
/usr/local/bin/runixo-agent -config /etc/runixo/agent.yaml
```
