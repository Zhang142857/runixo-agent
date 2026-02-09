<div align="center">
  <h1>🤖 Runixo Agent</h1>
  <p><strong>轻量级服务器管理 Agent</strong></p>
  <p>单个 Go 二进制 · ~15MB · <1% CPU · 零 Web 端口</p>

  <p>
    <a href="https://runixo.top">🌐 官网</a> ·
    <a href="https://runixo.top/guide/">📖 文档</a> ·
    <a href="https://github.com/Zhang142857/runixo-agent/releases">⬇️ 下载</a>
  </p>

  <p>
    <a href="https://github.com/Zhang142857/runixo-agent/releases"><img src="https://img.shields.io/github/v/release/Zhang142857/runixo-agent?style=flat-square&color=06b6d4" alt="Release"></a>
    <a href="https://github.com/Zhang142857/runixo-agent/blob/main/LICENSE"><img src="https://img.shields.io/github/license/Zhang142857/runixo-agent?style=flat-square" alt="License"></a>
    <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square&logo=go" alt="Go">
  </p>
</div>

---

## 📖 简介

Runixo Agent 是 [Runixo](https://github.com/Zhang142857/runixo) 服务器管理平台的 Agent 端。安装在你的服务器上，通过 gRPC + TLS 与桌面客户端安全通信。

**Agent 负责：**
- 📊 系统监控（CPU、内存、磁盘、网络、进程）
- 💻 命令执行（白名单控制、路径验证、审计日志）
- 🐳 Docker 管理（容器、镜像、网络、卷、Compose）
- 📁 文件操作（浏览、上传、下载、编辑）
- 🧩 插件托管（Agent 端插件运行环境）
- 🔄 自动更新（SHA256 校验，安全升级）

---

## 🔒 安全特性

| 特性 | 说明 |
|---|---|
| **零 Web 端口** | 不开放任何 HTTP 端口，仅 gRPC 通信 |
| **TLS 加密** | 所有通信端到端加密，自动生成证书 |
| **Token 认证** | 7 天自动过期，48 小时静默刷新窗口 |
| **命令白名单** | 默认开启，仅允许安全命令执行 |
| **路径访问控制** | 禁止访问 `/etc/passwd`、`/proc`、`/sys` 等敏感路径 |
| **暴力破解防护** | 自动锁定异常认证请求 |
| **更新校验** | SHA256 校验和验证，防止供应链攻击 |

---

## 🚀 安装

### 一键安装（推荐）

```bash
curl -fsSL https://raw.githubusercontent.com/Zhang142857/runixo-agent/main/scripts/install.sh | sudo bash
```

自动完成：下载二进制 → 创建 systemd 服务 → 生成 TLS 证书和 Token → 启动

安装后查看连接信息：

```bash
sudo runixo info
```

### 从客户端 SSH 安装

Runixo 客户端 → 服务器 → SSH 安装 → 输入连接信息 → 全自动完成。

### 手动安装

```bash
wget https://github.com/Zhang142857/runixo-agent/releases/latest/download/runixo-agent-linux_amd64.tar.gz
tar -xzf runixo-agent-linux_amd64.tar.gz
sudo mv runixo-agent /usr/local/bin/
sudo chmod +x /usr/local/bin/runixo-agent
sudo runixo-agent init
sudo systemctl start runixo-agent
sudo systemctl enable runixo-agent
```

---

## 🖥️ 支持平台

| 平台 | 架构 | 文件 |
|------|------|------|
| Linux | x86_64 | `runixo-agent-linux_amd64` |
| Linux | ARM64 | `runixo-agent-linux_arm64` |
| Linux | ARMv7 | `runixo-agent-linux_armv7` |
| Linux | x86 | `runixo-agent-linux_386` |
| macOS | x86_64 | `runixo-agent-darwin_amd64` |
| macOS | ARM64 (M1/M2) | `runixo-agent-darwin_arm64` |
| FreeBSD | x86_64 | `runixo-agent-freebsd_amd64` |

---

## ⚙️ 配置

配置文件：`/etc/runixo/config.yaml`

```yaml
server:
  host: "0.0.0.0"
  port: 9527
  tls:
    enabled: true          # TLS 加密（强烈建议开启）
    cert: "/etc/runixo/cert.pem"
    key: "/etc/runixo/key.pem"

auth:
  token: ""                # 自动生成

metrics:
  interval: 2              # 监控采集间隔（秒）

log:
  level: "info"            # debug / info / warn / error

update:
  auto: false              # 自动更新
  channel: "stable"
```

完整配置参考 [config.example.yaml](config.example.yaml)。

---

## 🏗️ 架构

```
runixo-agent/
├── cmd/agent/          # 入口
├── internal/
│   ├── server/         # gRPC 服务（命令、Docker、文件、监控）
│   ├── collector/      # 系统指标采集
│   ├── executor/       # 命令执行引擎（安全验证）
│   ├── auth/           # Token 认证 + 会话管理
│   ├── security/       # 命令白名单、路径验证
│   ├── plugin/         # Agent 端插件管理
│   ├── updater/        # 自动更新（SHA256 校验）
│   ├── audit/          # 审计日志
│   ├── ratelimit/      # 速率限制
│   └── emergency/      # 紧急资源保护
├── proto/              # Protocol Buffers 定义
└── scripts/            # 安装 / 卸载脚本
```

---

## 🔨 从源码构建

```bash
go build -o runixo-agent ./cmd/agent

# 或使用 Make
make build          # 构建当前平台
make build-all      # 构建所有平台
make test           # 运行测试
```

---

## 🗑️ 卸载

```bash
curl -fsSL https://raw.githubusercontent.com/Zhang142857/runixo-agent/main/scripts/uninstall.sh | sudo bash
```

---

## 📦 相关仓库

| 仓库 | 说明 |
|---|---|
| [**runixo**](https://github.com/Zhang142857/runixo) | 桌面客户端（Electron + Vue 3） |
| [**runixo-sdk**](https://github.com/Zhang142857/runixo-sdk) | 插件开发 SDK（TypeScript） |

---

## 📄 License

[MIT](LICENSE)
