package api

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/runixo/agent/internal/collector"
)

// Server REST API 服务器
type Server struct {
	collector      *collector.Collector
	token          string
	version        string
	failedAttempts map[string]*apiAttemptInfo
	mu             sync.RWMutex
}

type apiAttemptInfo struct {
	count       int
	lockedUntil time.Time
	lastAttempt time.Time
}

// NewServer 创建 API 服务器
func NewServer(token, version string) *Server {
	s := &Server{
		collector:      collector.New(),
		token:          token,
		version:        version,
		failedAttempts: make(map[string]*apiAttemptInfo),
	}
	go s.cleanupLoop()
	return s
}

// cleanupLoop 定期清理过期的失败记录
func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for ip, info := range s.failedAttempts {
			if now.After(info.lockedUntil) && now.Sub(info.lastAttempt) > 30*time.Minute {
				delete(s.failedAttempts, ip)
			}
		}
		s.mu.Unlock()
	}
}

// Response API 响应结构
type Response struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

func (s *Server) recordAPIFailedAttempt(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.failedAttempts[ip]; !exists {
		s.failedAttempts[ip] = &apiAttemptInfo{}
	}
	info := s.failedAttempts[ip]
	info.count++
	info.lastAttempt = time.Now()
	if info.count >= 5 {
		info.lockedUntil = time.Now().Add(15 * time.Minute)
	}
}

// authMiddleware 认证中间件（常量时间比较 + 暴力破解防护）
func (s *Server) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr

		// 检查是否被锁定
		s.mu.RLock()
		info, exists := s.failedAttempts[ip]
		s.mu.RUnlock()
		if exists && time.Now().Before(info.lockedUntil) {
			w.Header().Set("Retry-After", "900")
			s.jsonError(w, "Too many failed attempts", http.StatusTooManyRequests)
			return
		}

		auth := r.Header.Get("Authorization")
		if auth == "" {
			s.recordAPIFailedAttempt(ip)
			s.jsonError(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		// 常量时间比较防止时序攻击
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
			s.recordAPIFailedAttempt(ip)
			s.jsonError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// 认证成功，清除失败记录
		s.mu.Lock()
		delete(s.failedAttempts, ip)
		s.mu.Unlock()

		next(w, r)
	}
}

// securityHeaders 安全响应头中间件（移除 CORS 通配符）
func (s *Server) securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next(w, r)
	}
}

// jsonResponse 发送 JSON 响应
func (s *Server) jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(Response{Success: true, Data: data})
}

// jsonError 发送错误响应
func (s *Server) jsonError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(Response{Success: false, Error: message})
}

// RegisterRoutes 注册路由
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// 公开端点（仅健康检查和版本）
	mux.HandleFunc("/api/health", s.securityHeaders(s.handleHealth))
	mux.HandleFunc("/api/version", s.securityHeaders(s.handleVersion))

	// 需要认证的端点
	mux.HandleFunc("/api/system", s.securityHeaders(s.authMiddleware(s.handleSystemInfo)))
	mux.HandleFunc("/api/metrics", s.securityHeaders(s.authMiddleware(s.handleMetrics)))
	mux.HandleFunc("/api/processes", s.securityHeaders(s.authMiddleware(s.handleProcesses)))
}

// handleHealth 健康检查
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
	})
}

// handleVersion 版本信息
func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	s.jsonResponse(w, map[string]string{
		"version": s.version,
		"name":    "Runixo Agent",
	})
}

// handleSystemInfo 系统信息
func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	info, err := s.collector.GetSystemInfo()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to get system info: %v", err), http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, info)
}

// handleMetrics 监控指标
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	metrics, err := s.collector.GetMetrics()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to get metrics: %v", err), http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, metrics)
}

// handleProcesses 进程列表
func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	processes, err := s.collector.ListProcesses()
	if err != nil {
		s.jsonError(w, fmt.Sprintf("Failed to list processes: %v", err), http.StatusInternalServerError)
		return
	}
	s.jsonResponse(w, processes)
}
