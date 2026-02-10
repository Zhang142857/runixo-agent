package security

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// SecurityConfig 安全配置
type SecurityConfig struct {
	// 是否启用命令白名单模式（只允许白名单中的命令）
	EnableCommandWhitelist bool
	// 命令白名单
	CommandWhitelist []string
	// 危险命令黑名单（始终禁止）
	DangerousCommands []string
	// 是否允许 sudo
	AllowSudo bool
	// 允许访问的目录（文件操作）
	AllowedPaths []string
	// 禁止访问的目录
	ForbiddenPaths []string
	// 最大命令长度
	MaxCommandLength int
	// 最大参数数量
	MaxArguments int
}

// DefaultSecurityConfig 返回默认安全配置
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		EnableCommandWhitelist: true,
		CommandWhitelist: []string{
			// 系统信息
			"uname", "hostname", "uptime", "whoami", "id", "date", "cal",
			// 文件操作（只读）
			"ls", "cat", "head", "tail", "less", "more", "file", "stat", "wc", "du", "df",
			"find", "locate", "which", "whereis", "readlink",
			// 文本处理
			"grep", "awk", "sed", "cut", "sort", "uniq", "tr", "diff", "comm",
			// 网络诊断
			"ping", "traceroute", "nslookup", "dig", "host", "netstat", "ss", "ip", "ifconfig",
			"curl", "wget",
			// 进程管理
			"ps", "top", "htop", "pgrep", "pidof", "lsof",
			// 服务管理
			"systemctl", "service", "journalctl",
			// Docker
			"docker", "docker-compose",
			// 包管理
			"apt", "apt-get", "yum", "dnf", "pacman", "rpm", "dpkg",
			// 其他常用（注意：交互式 shell 通过 ExecuteShell 走，不在此白名单）
			"echo", "printf", "env", "printenv", "free", "vmstat", "iostat",
			"tar", "gzip", "gunzip", "zip", "unzip", "xz", "mkdir", "cp", "mv", "touch",
			"ssh-keygen", "openssl",
			"git", "npm", "node", "npx", "yarn", "pnpm",
			"python", "python3", "pip", "pip3",
			"nginx", "mysql", "psql", "redis-cli", "redis-server", "mongo", "mongod",
			"go", "java", "php", "composer",
			// 安装脚本需要的命令
			"tee", "ln", "test", "true", "false", "sleep",
		},
		DangerousCommands: []string{
			// 系统破坏性命令
			"rm -rf /", "rm -rf /*", "rm -rf ~",
			"mkfs", "fdisk", "parted", "dd if=/dev/zero",
			":(){ :|:& };:", // fork bomb
			// 权限相关
			"chmod 777 /", "chown -R /",
			// 网络攻击工具
			"nmap -sS", "hping3", "slowloris",
			// 危险的 shell 操作
			"> /dev/sda", "mv /* /dev/null",
		},
		AllowSudo:        false, // 默认禁用 sudo（需要时在配置中开启）
		AllowedPaths:     []string{"/home", "/var", "/tmp", "/opt", "/etc", "/usr"},
		ForbiddenPaths:   []string{"/etc/shadow", "/etc/sudoers", "/etc/passwd", "/root/.ssh", "/proc", "/sys"},
		MaxCommandLength: 50000,
		MaxArguments:     200,
	}
}

// CommandValidator 命令验证器
type CommandValidator struct {
	config *SecurityConfig
}

// NewCommandValidator 创建命令验证器
func NewCommandValidator(config *SecurityConfig) *CommandValidator {
	if config == nil {
		config = DefaultSecurityConfig()
	}
	return &CommandValidator{config: config}
}

// ValidateCommand 验证命令是否安全
func (v *CommandValidator) ValidateCommand(command string, args []string, sudo bool) error {
	// 检查命令长度
	fullCommand := command + " " + strings.Join(args, " ")
	if len(fullCommand) > v.config.MaxCommandLength {
		return fmt.Errorf("命令长度超过限制 (%d > %d)", len(fullCommand), v.config.MaxCommandLength)
	}

	// 检查参数数量
	if len(args) > v.config.MaxArguments {
		return fmt.Errorf("参数数量超过限制 (%d > %d)", len(args), v.config.MaxArguments)
	}

	// 检查 sudo 权限
	if sudo && !v.config.AllowSudo {
		return fmt.Errorf("sudo 执行已被禁用")
	}

	// sudo 命令白名单检查
	if sudo {
		sudoWhitelist := map[string]bool{
			"systemctl": true, "service": true, "journalctl": true,
			"apt": true, "apt-get": true, "yum": true, "dnf": true, "pacman": true, "zypper": true,
			"mkdir": true, "chown": true, "chmod": true, "cp": true, "mv": true,
			"docker": true, "runixo": true,
		}
		if !sudoWhitelist[command] {
			return fmt.Errorf("命令 '%s' 不允许使用 sudo", command)
		}
	}

	// 检查危险命令
	if err := v.checkDangerousCommand(fullCommand); err != nil {
		return err
	}

	// 如果启用白名单模式，检查命令是否在白名单中
	if v.config.EnableCommandWhitelist {
		if !v.isCommandAllowed(command) {
			return fmt.Errorf("命令 '%s' 不在允许列表中", command)
		}
	}

	return nil
}

// checkDangerousCommand 检查危险命令
func (v *CommandValidator) checkDangerousCommand(fullCommand string) error {
	lowerCmd := strings.ToLower(fullCommand)

	for _, dangerous := range v.config.DangerousCommands {
		if strings.Contains(lowerCmd, strings.ToLower(dangerous)) {
			return fmt.Errorf("检测到危险命令: %s", dangerous)
		}
	}

	// 检查危险模式
	dangerousPatterns := []struct {
		pattern string
		desc    string
	}{
		{`rm\s+(-[rf]+\s+)*(/\s|/\*|\.\.)`, "危险的 rm 命令"},
		{`>\s*/dev/[sh]d[a-z]`, "尝试覆盖磁盘设备"},
		{`dd\s+.*of=/dev/[sh]d[a-z]`, "尝试写入磁盘设备"},
		{`:\(\)\s*\{.*\}`, "检测到 fork bomb"},
	}

	for _, dp := range dangerousPatterns {
		matched, _ := regexp.MatchString(dp.pattern, lowerCmd)
		if matched {
			return fmt.Errorf("安全检查失败: %s", dp.desc)
		}
	}

	return nil
}

// isCommandAllowed 检查命令是否在白名单中
func (v *CommandValidator) isCommandAllowed(command string) bool {
	// 获取命令的基本名称（去除路径）
	baseName := filepath.Base(command)

	for _, allowed := range v.config.CommandWhitelist {
		if baseName == allowed || command == allowed {
			return true
		}
	}
	return false
}

// PathValidator 路径验证器
type PathValidator struct {
	config *SecurityConfig
}

// NewPathValidator 创建路径验证器
func NewPathValidator(config *SecurityConfig) *PathValidator {
	if config == nil {
		config = DefaultSecurityConfig()
	}
	return &PathValidator{config: config}
}

// ValidatePath 验证路径是否安全
func (v *PathValidator) ValidatePath(path string) error {
	// 清理路径
	cleanPath := filepath.Clean(path)

	// 检查路径遍历攻击
	if strings.Contains(path, "..") {
		if strings.Contains(cleanPath, "..") {
			return fmt.Errorf("检测到路径遍历攻击")
		}
	}

	// 检查绝对路径
	if !filepath.IsAbs(cleanPath) {
		return fmt.Errorf("必须使用绝对路径")
	}

	// 解析符号链接，防止通过 symlink 绕过路径检查
	realPath, err := filepath.EvalSymlinks(cleanPath)
	if err == nil && realPath != cleanPath {
		// 对真实路径也执行禁止路径检查
		for _, forbidden := range v.config.ForbiddenPaths {
			if strings.HasPrefix(realPath, forbidden) {
				return fmt.Errorf("符号链接目标路径被禁止: %s", forbidden)
			}
		}
		cleanPath = realPath
	}

	// 检查禁止访问的路径
	for _, forbidden := range v.config.ForbiddenPaths {
		if strings.HasPrefix(cleanPath, forbidden) {
			return fmt.Errorf("禁止访问路径: %s", forbidden)
		}
	}

	return nil
}

// ValidatePathForWrite 验证写入路径是否安全
func (v *PathValidator) ValidatePathForWrite(path string) error {
	if err := v.ValidatePath(path); err != nil {
		return err
	}

	writeRestrictedPaths := []string{
		"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/sudoers",
		"/etc/ssh/sshd_config", "/etc/crontab",
		"/boot", "/usr/bin", "/usr/sbin", "/bin", "/sbin",
	}

	cleanPath := filepath.Clean(path)
	for _, restricted := range writeRestrictedPaths {
		if strings.HasPrefix(cleanPath, restricted) {
			return fmt.Errorf("禁止写入系统关键路径: %s", restricted)
		}
	}

	return nil
}

// SanitizePath 清理并验证路径
func SanitizePath(path string) (string, error) {
	cleanPath := filepath.Clean(path)

	if !filepath.IsAbs(cleanPath) {
		return "", fmt.Errorf("必须使用绝对路径")
	}

	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("路径包含非法字符")
	}

	return cleanPath, nil
}
