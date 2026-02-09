// Package ratelimit 提供请求速率限制功能
// 设计原则：安全但不影响正常使用
package ratelimit

import (
	"context"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Config 速率限制配置
type Config struct {
	// 是否启用速率限制
	Enabled bool `json:"enabled"`
	// 每分钟最大请求数（全局）
	RequestsPerMinute int `json:"requests_per_minute"`
	// 每分钟最大命令执行数
	CommandsPerMinute int `json:"commands_per_minute"`
	// 每分钟最大文件操作数
	FileOpsPerMinute int `json:"file_ops_per_minute"`
	// 突发容量（允许短时间超出限制）
	BurstSize int `json:"burst_size"`
}

// DefaultConfig 返回默认配置（宽松但安全）
func DefaultConfig() *Config {
	return &Config{
		Enabled:           true,
		RequestsPerMinute: 600,
		CommandsPerMinute: 200,
		FileOpsPerMinute:  300,
		BurstSize:         50,
	}
}

// Limiter 速率限制器
type Limiter struct {
	config   *Config
	counters map[string]*clientCounter
	mu       sync.RWMutex
}

// clientCounter 客户端计数器
type clientCounter struct {
	requests  *tokenBucket
	commands  *tokenBucket
	fileOps   *tokenBucket
	lastSeen  time.Time
}

// tokenBucket 令牌桶算法实现
type tokenBucket struct {
	tokens     float64
	maxTokens  float64
	refillRate float64 // 每秒补充的令牌数
	lastRefill time.Time
	mu         sync.Mutex
}

// newTokenBucket 创建令牌桶
func newTokenBucket(maxTokens float64, refillPerMinute int) *tokenBucket {
	return &tokenBucket{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: float64(refillPerMinute) / 60.0,
		lastRefill: time.Now(),
	}
}

// allow 检查是否允许请求
func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	// 补充令牌
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()
	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.maxTokens {
		tb.tokens = tb.maxTokens
	}
	tb.lastRefill = now

	// 检查是否有足够令牌
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// NewLimiter 创建速率限制器
func NewLimiter(config *Config) *Limiter {
	if config == nil {
		config = DefaultConfig()
	}

	l := &Limiter{
		config:   config,
		counters: make(map[string]*clientCounter),
	}

	// 启动清理协程
	go l.cleanupLoop()

	return l
}

// getClientIP 获取客户端IP
func getClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}

// getOrCreateCounter 获取或创建客户端计数器
func (l *Limiter) getOrCreateCounter(clientIP string) *clientCounter {
	l.mu.Lock()
	defer l.mu.Unlock()

	if counter, exists := l.counters[clientIP]; exists {
		counter.lastSeen = time.Now()
		return counter
	}

	counter := &clientCounter{
		requests: newTokenBucket(float64(l.config.BurstSize), l.config.RequestsPerMinute),
		commands: newTokenBucket(float64(l.config.BurstSize/2), l.config.CommandsPerMinute),
		fileOps:  newTokenBucket(float64(l.config.BurstSize), l.config.FileOpsPerMinute),
		lastSeen: time.Now(),
	}
	l.counters[clientIP] = counter
	return counter
}

// AllowRequest 检查是否允许普通请求
func (l *Limiter) AllowRequest(ctx context.Context) bool {
	if !l.config.Enabled {
		return true
	}

	clientIP := getClientIP(ctx)
	counter := l.getOrCreateCounter(clientIP)
	return counter.requests.allow()
}

// AllowCommand 检查是否允许命令执行
func (l *Limiter) AllowCommand(ctx context.Context) bool {
	if !l.config.Enabled {
		return true
	}

	clientIP := getClientIP(ctx)
	counter := l.getOrCreateCounter(clientIP)
	return counter.commands.allow()
}

// AllowFileOp 检查是否允许文件操作
func (l *Limiter) AllowFileOp(ctx context.Context) bool {
	if !l.config.Enabled {
		return true
	}

	clientIP := getClientIP(ctx)
	counter := l.getOrCreateCounter(clientIP)
	return counter.fileOps.allow()
}

// cleanupLoop 清理过期的计数器
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		l.cleanup()
	}
}

// cleanup 清理过期计数器
func (l *Limiter) cleanup() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-10 * time.Minute)
	for ip, counter := range l.counters {
		if counter.lastSeen.Before(cutoff) {
			delete(l.counters, ip)
		}
	}
}

// UnaryInterceptor 一元调用拦截器
func (l *Limiter) UnaryInterceptor() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		if !l.config.Enabled {
			return handler(ctx, req)
		}

		// 根据方法类型选择不同的限制
		var allowed bool
		switch {
		case isCommandMethod(info.FullMethod):
			allowed = l.AllowCommand(ctx)
		case isFileMethod(info.FullMethod):
			allowed = l.AllowFileOp(ctx)
		default:
			allowed = l.AllowRequest(ctx)
		}

		if !allowed {
			return nil, status.Error(codes.ResourceExhausted, "请求过于频繁，请稍后重试")
		}

		return handler(ctx, req)
	}
}

// StreamInterceptor 流式调用拦截器
func (l *Limiter) StreamInterceptor() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if !l.config.Enabled {
			return handler(srv, ss)
		}

		if !l.AllowRequest(ss.Context()) {
			return status.Error(codes.ResourceExhausted, "请求过于频繁，请稍后重试")
		}

		return handler(srv, ss)
	}
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

// isFileMethod 检查是否为文件操作方法
func isFileMethod(method string) bool {
	fileMethods := []string{
		"ReadFile",
		"WriteFile",
		"DeleteFile",
		"ListDirectory",
		"UploadFile",
		"DownloadFile",
	}
	for _, m := range fileMethods {
		if contains(method, m) {
			return true
		}
	}
	return false
}

// contains 检查字符串是否包含子串
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// SetConfig 更新配置
func (l *Limiter) SetConfig(config *Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.config = config
}

// GetConfig 获取当前配置
func (l *Limiter) GetConfig() *Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.config
}

// GetStats 获取统计信息
func (l *Limiter) GetStats() map[string]interface{} {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return map[string]interface{}{
		"enabled":        l.config.Enabled,
		"active_clients": len(l.counters),
		"config":         l.config,
	}
}
