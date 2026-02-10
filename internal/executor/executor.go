package executor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/runixo/agent/internal/security"
)

// 全局安全验证器
var (
	cmdValidator  *security.CommandValidator
	pathValidator *security.PathValidator
)

// 缓冲区池：复用命令输出读取缓冲区
var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024) // 32KB
		return &buf
	},
}

func init() {
	config := security.DefaultSecurityConfig()
	cmdValidator = security.NewCommandValidator(config)
	pathValidator = security.NewPathValidator(config)
}

// Options 执行选项
type Options struct {
	WorkingDir string
	Env        map[string]string
	Timeout    time.Duration
	Sudo       bool
}

// Result 执行结果
type Result struct {
	ExitCode   int
	Stdout     string
	Stderr     string
	DurationMs int64
}

// FileInfo 文件信息
type FileInfo struct {
	Name    string
	Path    string
	Size    int64
	Mode    int64
	ModTime int64
	IsDir   bool
	Owner   string
	Group   string
}

// ServiceInfo 服务信息
type ServiceInfo struct {
	Name        string
	Status      string
	Description string
	Enabled     bool
	Pid         int32
	Uptime      int64
}

// Execute 执行命令（带安全检查）
func Execute(ctx context.Context, command string, args []string, opts Options) (*Result, error) {
	// 安全检查：验证命令
	if err := cmdValidator.ValidateCommand(command, args, opts.Sudo); err != nil {
		return &Result{
			ExitCode: -1,
			Stderr:   fmt.Sprintf("安全检查失败: %s", err.Error()),
		}, nil
	}

	// 安全检查：验证工作目录
	if opts.WorkingDir != "" {
		if err := pathValidator.ValidatePath(opts.WorkingDir); err != nil {
			return &Result{
				ExitCode: -1,
				Stderr:   fmt.Sprintf("工作目录安全检查失败: %s", err.Error()),
			}, nil
		}
	}

	start := time.Now()

	// 创建带超时的上下文
	if opts.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
	}

	// 构建命令
	var cmd *exec.Cmd
	if opts.Sudo {
		allArgs := append([]string{command}, args...)
		cmd = exec.CommandContext(ctx, "sudo", allArgs...)
	} else {
		cmd = exec.CommandContext(ctx, command, args...)
	}

	// 设置工作目录
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	}

	// 设置环境变量（过滤危险变量）
	cmd.Env = FilterEnvVars(os.Environ())
	for k, v := range opts.Env {
		// 验证环境变量名
		if IsValidEnvVar(k) {
			cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// 捕获输出
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("创建 stdout 管道失败: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("创建 stderr 管道失败: %w", err)
	}

	// 启动命令
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动命令失败: %w", err)
	}

	// 读取输出（限制大小，处理错误）
	const maxOutputSize = 10 * 1024 * 1024 // 10MB
	stdoutBytes, stdoutErr := io.ReadAll(io.LimitReader(stdout, maxOutputSize))
	stderrBytes, stderrErr := io.ReadAll(io.LimitReader(stderr, maxOutputSize))

	// 等待完成
	err = cmd.Wait()

	result := &Result{
		Stdout:     string(stdoutBytes),
		Stderr:     string(stderrBytes),
		DurationMs: time.Since(start).Milliseconds(),
	}

	if stdoutErr != nil || stderrErr != nil {
		result.Stderr += "\n[警告] 读取输出时发生错误"
	}

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			result.ExitCode = exitErr.ExitCode()
		} else if ctx.Err() == context.DeadlineExceeded {
			result.ExitCode = -1
			result.Stderr = "命令执行超时"
		} else {
			return nil, err
		}
	}

	return result, nil
}

// FilterEnvVars 过滤危险的环境变量
func FilterEnvVars(envs []string) []string {
	dangerousVars := map[string]bool{
		"LD_PRELOAD":            true,
		"LD_LIBRARY_PATH":      true,
		"DYLD_INSERT_LIBRARIES": true,
		"BASH_ENV":              true,
		"ENV":                   true,
		"PROMPT_COMMAND":        true,
		// 语言运行时路径注入
		"PYTHONPATH":  true,
		"PERL5LIB":   true,
		"PERLLIB":     true,
		"NODE_PATH":   true,
		"RUBYLIB":     true,
		"CLASSPATH":   true,
		"LUA_PATH":    true,
		"LUA_CPATH":   true,
	}

	var filtered []string
	for _, env := range envs {
		parts := strings.SplitN(env, "=", 2)
		if len(parts) == 2 && !dangerousVars[parts[0]] {
			filtered = append(filtered, env)
		}
	}
	return filtered
}

// IsValidEnvVar 验证环境变量名是否合法
func IsValidEnvVar(name string) bool {
	if len(name) == 0 {
		return false
	}
	// 环境变量名只能包含字母、数字和下划线，且不能以数字开头
	for i, c := range name {
		if i == 0 && c >= '0' && c <= '9' {
			return false
		}
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}

// ReadFile 读取文件（带安全检查）
func ReadFile(path string) ([]byte, *FileInfo, error) {
	// 安全检查
	cleanPath, err := security.SanitizePath(path)
	if err != nil {
		return nil, nil, fmt.Errorf("路径安全检查失败: %w", err)
	}

	if err := pathValidator.ValidatePath(cleanPath); err != nil {
		return nil, nil, fmt.Errorf("路径访问被拒绝: %w", err)
	}

	// 检查是否为符号链接（防止符号链接攻击）
	realPath, err := filepath.EvalSymlinks(cleanPath)
	if err == nil && realPath != cleanPath {
		// 重新验证真实路径
		if err := pathValidator.ValidatePath(realPath); err != nil {
			return nil, nil, fmt.Errorf("符号链接目标路径被拒绝: %w", err)
		}
		cleanPath = realPath
	}

	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, nil, err
	}

	if info.IsDir() {
		return nil, nil, fmt.Errorf("路径是目录而非文件")
	}

	// 限制文件大小（防止读取超大文件导致内存耗尽）
	const maxFileSize = 50 * 1024 * 1024 // 50MB
	if info.Size() > maxFileSize {
		return nil, nil, fmt.Errorf("文件过大，超过 50MB 限制")
	}

	content, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, nil, err
	}

	fileInfo := &FileInfo{
		Name:    info.Name(),
		Path:    cleanPath,
		Size:    info.Size(),
		Mode:    int64(info.Mode()),
		ModTime: info.ModTime().Unix(),
		IsDir:   false,
	}

	return content, fileInfo, nil
}

// WriteFile 写入文件（带安全检查）
func WriteFile(path string, content []byte, mode int64, createDirs bool) error {
	// 安全检查
	cleanPath, err := security.SanitizePath(path)
	if err != nil {
		return fmt.Errorf("路径安全检查失败: %w", err)
	}

	if err := pathValidator.ValidatePathForWrite(cleanPath); err != nil {
		return fmt.Errorf("写入路径被拒绝: %w", err)
	}

	// 限制写入内容大小
	const maxWriteSize = 50 * 1024 * 1024 // 50MB
	if len(content) > maxWriteSize {
		return fmt.Errorf("写入内容过大，超过 50MB 限制")
	}

	if createDirs {
		dir := filepath.Dir(cleanPath)
		// 验证目录路径
		if err := pathValidator.ValidatePathForWrite(dir); err != nil {
			return fmt.Errorf("目录路径被拒绝: %w", err)
		}
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("创建目录失败: %w", err)
		}
	}

	fileMode := os.FileMode(mode)
	if fileMode == 0 {
		fileMode = 0644
	}

	// 限制文件权限，不允许设置可执行位（除非明确需要）
	if fileMode&0111 != 0 {
		// 如果设置了可执行位，记录警告但仍然允许
		// 在更严格的模式下可以拒绝
	}

	return os.WriteFile(cleanPath, content, fileMode)
}

// ListDirectory 列出目录（带安全检查）
func ListDirectory(path string, recursive bool, showHidden bool) ([]*FileInfo, error) {
	// 安全检查
	cleanPath, err := security.SanitizePath(path)
	if err != nil {
		return nil, fmt.Errorf("路径安全检查失败: %w", err)
	}

	if err := pathValidator.ValidatePath(cleanPath); err != nil {
		return nil, fmt.Errorf("路径访问被拒绝: %w", err)
	}

	var files []*FileInfo

	if recursive {
		err := filepath.Walk(cleanPath, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return nil // 跳过无法访问的文件
			}

			// 跳过隐藏文件
			if !showHidden && len(info.Name()) > 0 && info.Name()[0] == '.' {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			files = append(files, &FileInfo{
				Name:    info.Name(),
				Path:    p,
				Size:    info.Size(),
				Mode:    int64(info.Mode()),
				ModTime: info.ModTime().Unix(),
				IsDir:   info.IsDir(),
			})
			return nil
		})
		return files, err
	}

	entries, err := os.ReadDir(cleanPath)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		// 跳过隐藏文件
		if !showHidden && len(entry.Name()) > 0 && entry.Name()[0] == '.' {
			continue
		}

		info, err := entry.Info()
		if err != nil {
			continue
		}

		files = append(files, &FileInfo{
			Name:    info.Name(),
			Path:    filepath.Join(cleanPath, info.Name()),
			Size:    info.Size(),
			Mode:    int64(info.Mode()),
			ModTime: info.ModTime().Unix(),
			IsDir:   info.IsDir(),
		})
	}

	return files, nil
}

// TailFile 实时读取文件（带安全检查）
func TailFile(ctx context.Context, path string, lines int, follow bool) (<-chan string, error) {
	// 安全检查
	cleanPath, err := security.SanitizePath(path)
	if err != nil {
		return nil, fmt.Errorf("路径安全检查失败: %w", err)
	}

	if err := pathValidator.ValidatePath(cleanPath); err != nil {
		return nil, fmt.Errorf("路径访问被拒绝: %w", err)
	}

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, err
	}

	lineChan := make(chan string, 100)

	go func() {
		defer file.Close()
		defer close(lineChan)

		// 读取最后 N 行
		scanner := bufio.NewScanner(file)
		var buffer []string
		for scanner.Scan() {
			buffer = append(buffer, scanner.Text())
			if len(buffer) > lines {
				buffer = buffer[1:]
			}
		}

		for _, line := range buffer {
			select {
			case <-ctx.Done():
				return
			case lineChan <- line:
			}
		}

		if !follow {
			return
		}

		// 持续监听新内容（使用递增退避，避免 busy-wait）
		backoff := 200 * time.Millisecond
		maxBackoff := 2 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if scanner.Scan() {
					lineChan <- scanner.Text()
					backoff = 200 * time.Millisecond // 有新内容时重置退避
				} else {
					time.Sleep(backoff)
					if backoff < maxBackoff {
						backoff = backoff * 3 / 2 // 1.5x 递增
					}
				}
			}
		}
	}()

	return lineChan, nil
}

// ListServices 列出系统服务
func ListServices(ctx context.Context) ([]*ServiceInfo, error) {
	// 使用 systemctl 列出服务
	cmd := exec.CommandContext(ctx, "systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var services []*ServiceInfo
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// 跳过标题行
	scanner.Scan()

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}

		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		name := strings.TrimSuffix(fields[0], ".service")
		status := fields[3]

		services = append(services, &ServiceInfo{
			Name:   name,
			Status: status,
		})
	}

	return services, nil
}

// ServiceAction 服务操作
func ServiceAction(ctx context.Context, name string, action string) error {
	// 验证操作类型
	allowedActions := map[string]bool{
		"start":   true,
		"stop":    true,
		"restart": true,
		"reload":  true,
		"status":  true,
		"enable":  true,
		"disable": true,
	}

	if !allowedActions[action] {
		return fmt.Errorf("不允许的服务操作: %s", action)
	}

	// 验证服务名（防止命令注入）
	if strings.ContainsAny(name, ";|&$`(){}[]<>\\\"' \t\n\r") {
		return fmt.Errorf("服务名包含非法字符")
	}

	cmd := exec.CommandContext(ctx, "systemctl", action, name)
	return cmd.Run()
}

// KillProcess 终止进程
func KillProcess(pid int, signal int) error {
	// 验证 PID
	if pid <= 1 {
		return fmt.Errorf("不允许终止 PID <= 1 的进程")
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	sig := syscall.Signal(signal)
	if signal == 0 {
		sig = syscall.SIGTERM
	}

	// 只允许特定信号
	allowedSignals := map[syscall.Signal]bool{
		syscall.SIGTERM: true,
		syscall.SIGKILL: true,
		syscall.SIGINT:  true,
		syscall.SIGHUP:  true,
	}

	if !allowedSignals[sig] {
		return fmt.Errorf("不允许的信号: %d", signal)
	}

	return process.Signal(sig)
}
