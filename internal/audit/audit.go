// Package audit 提供审计日志功能
// 设计原则：记录关键操作，不影响性能
package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/peer"
)

// EventType 事件类型
type EventType string

const (
	EventTypeAuth       EventType = "auth"        // 认证事件
	EventTypeCommand    EventType = "command"     // 命令执行
	EventTypeFile       EventType = "file"        // 文件操作
	EventTypeSecurity   EventType = "security"    // 安全事件
	EventTypeSystem     EventType = "system"      // 系统事件
)

// EventLevel 事件级别
type EventLevel string

const (
	LevelInfo    EventLevel = "info"
	LevelWarning EventLevel = "warning"
	LevelError   EventLevel = "error"
	LevelCritical EventLevel = "critical"
)

// Event 审计事件
type Event struct {
	ID        string                 `json:"id"`
	Timestamp time.Time              `json:"timestamp"`
	Type      EventType              `json:"type"`
	Level     EventLevel             `json:"level"`
	Action    string                 `json:"action"`
	ClientIP  string                 `json:"client_ip"`
	Success   bool                   `json:"success"`
	Message   string                 `json:"message,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// Config 审计配置
type Config struct {
	// 是否启用审计
	Enabled bool `json:"enabled"`
	// 日志文件路径
	LogPath string `json:"log_path"`
	// 最大日志文件大小（MB）
	MaxSizeMB int `json:"max_size_mb"`
	// 保留的日志文件数量
	MaxBackups int `json:"max_backups"`
	// 记录的最低级别
	MinLevel EventLevel `json:"min_level"`
	// 是否记录成功的认证
	LogSuccessAuth bool `json:"log_success_auth"`
	// 是否记录命令执行
	LogCommands bool `json:"log_commands"`
	// 是否记录文件操作
	LogFileOps bool `json:"log_file_ops"`
}

// DefaultConfig 返回默认配置（平衡安全和性能）
func DefaultConfig() *Config {
	return &Config{
		Enabled:        true,
		LogPath:        "/var/log/runixo/audit.log",
		MaxSizeMB:      50,
		MaxBackups:     5,
		MinLevel:       LevelInfo,
		LogSuccessAuth: false, // 默认不记录成功认证，减少日志量
		LogCommands:    true,  // 记录命令执行
		LogFileOps:     false, // 默认不记录文件操作，太频繁
	}
}

// Logger 审计日志记录器
type Logger struct {
	config    *Config
	file      *os.File
	mu        sync.Mutex
	eventChan chan *Event
	done      chan struct{}
}

// NewLogger 创建审计日志记录器
func NewLogger(config *Config) (*Logger, error) {
	if config == nil {
		config = DefaultConfig()
	}

	l := &Logger{
		config:    config,
		eventChan: make(chan *Event, 1000),
		done:      make(chan struct{}),
	}

	if config.Enabled {
		if err := l.openLogFile(); err != nil {
			// 如果无法打开日志文件，禁用审计但不报错
			config.Enabled = false
		}
	}

	// 启动异步写入协程
	go l.writeLoop()

	return l, nil
}

// openLogFile 打开日志文件
func (l *Logger) openLogFile() error {
	dir := filepath.Dir(l.config.LogPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.OpenFile(l.config.LogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	l.file = file
	return nil
}

// Log 记录审计事件
func (l *Logger) Log(event *Event) {
	if !l.config.Enabled {
		return
	}

	// 检查级别
	if !l.shouldLog(event) {
		return
	}

	// 设置ID和时间戳
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// 异步写入
	select {
	case l.eventChan <- event:
	default:
		// 通道满了，丢弃事件（不阻塞主流程）
	}
}

// shouldLog 检查是否应该记录
func (l *Logger) shouldLog(event *Event) bool {
	// 检查级别
	if !isLevelAtLeast(event.Level, l.config.MinLevel) {
		return false
	}

	// 检查事件类型配置
	switch event.Type {
	case EventTypeAuth:
		if event.Success && !l.config.LogSuccessAuth {
			return false
		}
	case EventTypeCommand:
		if !l.config.LogCommands {
			return false
		}
	case EventTypeFile:
		if !l.config.LogFileOps {
			return false
		}
	}

	return true
}

// writeLoop 异步写入循环
func (l *Logger) writeLoop() {
	for {
		select {
		case event := <-l.eventChan:
			l.writeEvent(event)
		case <-l.done:
			// 写入剩余事件
			for {
				select {
				case event := <-l.eventChan:
					l.writeEvent(event)
				default:
					return
				}
			}
		}
	}
}

// writeEvent 写入单个事件
func (l *Logger) writeEvent(event *Event) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return
	}

	// 检查文件大小，必要时轮转
	l.checkRotate()

	// 写入JSON行
	data, err := json.Marshal(event)
	if err != nil {
		return
	}

	l.file.Write(data)
	l.file.Write([]byte("\n"))
}

// checkRotate 检查是否需要轮转日志
func (l *Logger) checkRotate() {
	if l.file == nil {
		return
	}

	info, err := l.file.Stat()
	if err != nil {
		return
	}

	maxSize := int64(l.config.MaxSizeMB) * 1024 * 1024
	if info.Size() < maxSize {
		return
	}

	// 关闭当前文件
	l.file.Close()

	// 轮转文件
	l.rotateFiles()

	// 重新打开
	l.openLogFile()
}

// rotateFiles 轮转日志文件
func (l *Logger) rotateFiles() {
	// 删除最旧的备份
	oldestBackup := fmt.Sprintf("%s.%d", l.config.LogPath, l.config.MaxBackups)
	os.Remove(oldestBackup)

	// 重命名现有备份
	for i := l.config.MaxBackups - 1; i >= 1; i-- {
		oldName := fmt.Sprintf("%s.%d", l.config.LogPath, i)
		newName := fmt.Sprintf("%s.%d", l.config.LogPath, i+1)
		os.Rename(oldName, newName)
	}

	// 重命名当前日志
	os.Rename(l.config.LogPath, l.config.LogPath+".1")
}

// Close 关闭日志记录器
func (l *Logger) Close() {
	close(l.done)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		l.file.Close()
		l.file = nil
	}
}

// LogAuth 记录认证事件
func (l *Logger) LogAuth(clientIP string, success bool, message string) {
	level := LevelInfo
	if !success {
		level = LevelWarning
	}

	l.Log(&Event{
		Type:     EventTypeAuth,
		Level:    level,
		Action:   "authenticate",
		ClientIP: clientIP,
		Success:  success,
		Message:  message,
	})
}

// LogCommand 记录命令执行
func (l *Logger) LogCommand(clientIP, command string, args []string, exitCode int) {
	l.Log(&Event{
		Type:     EventTypeCommand,
		Level:    LevelInfo,
		Action:   "execute_command",
		ClientIP: clientIP,
		Success:  exitCode == 0,
		Details: map[string]interface{}{
			"command":   command,
			"args":      args,
			"exit_code": exitCode,
		},
	})
}

// LogFileOp 记录文件操作
func (l *Logger) LogFileOp(clientIP, action, path string, success bool) {
	l.Log(&Event{
		Type:     EventTypeFile,
		Level:    LevelInfo,
		Action:   action,
		ClientIP: clientIP,
		Success:  success,
		Details: map[string]interface{}{
			"path": path,
		},
	})
}

// LogSecurity 记录安全事件
func (l *Logger) LogSecurity(clientIP, action, message string, level EventLevel) {
	l.Log(&Event{
		Type:     EventTypeSecurity,
		Level:    level,
		Action:   action,
		ClientIP: clientIP,
		Success:  false,
		Message:  message,
	})
}

// UnaryInterceptor 一元调用拦截器（用于自动记录）
func (l *Logger) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 只记录命令执行
		if !l.config.Enabled || !l.config.LogCommands {
			return handler(ctx, req)
		}

		clientIP := getClientIP(ctx)
		start := time.Now()

		resp, err := handler(ctx, req)

		// 记录命令执行方法
		if isCommandMethod(info.FullMethod) {
			l.Log(&Event{
				Type:     EventTypeCommand,
				Level:    LevelInfo,
				Action:   info.FullMethod,
				ClientIP: clientIP,
				Success:  err == nil,
				Details: map[string]interface{}{
					"duration_ms": time.Since(start).Milliseconds(),
				},
			})
		}

		return resp, err
	}
}

// getClientIP 获取客户端IP
func getClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}

// isCommandMethod 检查是否为命令执行方法
func isCommandMethod(method string) bool {
	commandMethods := []string{
		"ExecuteCommand",
		"ExecuteShell",
		"ServiceAction",
		"KillProcess",
	}
	for _, m := range commandMethods {
		if contains(method, m) {
			return true
		}
	}
	return false
}

// contains 检查字符串是否包含子串
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// isLevelAtLeast 检查级别是否达到最低要求
func isLevelAtLeast(level, minLevel EventLevel) bool {
	levels := map[EventLevel]int{
		LevelInfo:     0,
		LevelWarning:  1,
		LevelError:    2,
		LevelCritical: 3,
	}
	return levels[level] >= levels[minLevel]
}

// generateEventID 生成事件ID
func generateEventID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), time.Now().Nanosecond()%1000)
}

// SetConfig 更新配置
func (l *Logger) SetConfig(config *Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = config
}

// GetConfig 获取当前配置
func (l *Logger) GetConfig() *Config {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.config
}
