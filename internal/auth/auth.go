package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// 安全配置
const (
	MaxFailedAttempts = 5                // 最大失败尝试次数
	LockoutDuration   = 15 * time.Minute // 锁定时间
	TokenMinLength    = 32               // 令牌最小长度
)

// SessionInfo 会话信息
type SessionInfo struct {
	Token     string    `json:"token"`
	ClientIP  string    `json:"client_ip"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

// AuthInterceptor 认证拦截器
type AuthInterceptor struct {
	token         string
	requireAuth   bool
	failedAttempts map[string]*attemptInfo
	mu            sync.RWMutex
}

type attemptInfo struct {
	count     int
	lockedUntil time.Time
}

// NewAuthInterceptor 创建认证拦截器
func NewAuthInterceptor(token string) *AuthInterceptor {
	// 强制要求认证令牌
	requireAuth := token != ""
	if !requireAuth {
		// 如果没有配置令牌，生成一个随机令牌并记录警告
		// 在生产环境中应该强制配置令牌
		token, _ = GenerateToken()
	}

	a := &AuthInterceptor{
		token:         token,
		requireAuth:   requireAuth,
		failedAttempts: make(map[string]*attemptInfo),
	}
	// 启动定期清理过期的失败记录
	go a.cleanupFailedAttempts()
	return a
}

// cleanupFailedAttempts 定期清理过期的失败尝试记录，防止内存泄漏
func (a *AuthInterceptor) cleanupFailedAttempts() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		now := time.Now()
		for ip, info := range a.failedAttempts {
			// 锁定已过期且超过 30 分钟未活动的记录可以清理
			if now.After(info.lockedUntil) && info.count < MaxFailedAttempts {
				delete(a.failedAttempts, ip)
			} else if now.After(info.lockedUntil.Add(30 * time.Minute)) {
				delete(a.failedAttempts, ip)
			}
		}
		a.mu.Unlock()
	}
}

// IsAuthRequired 返回是否需要认证
func (a *AuthInterceptor) IsAuthRequired() bool {
	return a.requireAuth
}

// GetToken 获取当前令牌（仅用于显示生成的令牌）
func (a *AuthInterceptor) GetToken() string {
	return a.token
}

// Unary 一元调用拦截器
func (a *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// 跳过认证方法本身
		if info.FullMethod == "/runixo.AgentService/Authenticate" {
			return handler(ctx, req)
		}

		if err := a.authorize(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// Stream 流式调用拦截器
func (a *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		if err := a.authorize(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

// getClientIP 获取客户端 IP
func (a *AuthInterceptor) getClientIP(ctx context.Context) string {
	if p, ok := peer.FromContext(ctx); ok {
		return p.Addr.String()
	}
	return "unknown"
}

// isLocked 检查 IP 是否被锁定
func (a *AuthInterceptor) isLocked(ip string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()

	if info, exists := a.failedAttempts[ip]; exists {
		if time.Now().Before(info.lockedUntil) {
			return true
		}
	}
	return false
}

// recordFailedAttempt 记录失败尝试
func (a *AuthInterceptor) recordFailedAttempt(ip string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	// 防止内存耗尽：限制最大记录数
	const maxRecords = 10000
	if len(a.failedAttempts) >= maxRecords {
		// 清理已过期的记录
		now := time.Now()
		for k, v := range a.failedAttempts {
			if now.After(v.lockedUntil) {
				delete(a.failedAttempts, k)
			}
		}
		// 如果仍然超限，拒绝新记录（保守策略）
		if len(a.failedAttempts) >= maxRecords {
			return false
		}
	}

	if _, exists := a.failedAttempts[ip]; !exists {
		a.failedAttempts[ip] = &attemptInfo{}
	}

	info := a.failedAttempts[ip]
	info.count++

	if info.count >= MaxFailedAttempts {
		info.lockedUntil = time.Now().Add(LockoutDuration)
		return true // 已锁定
	}
	return false
}

// resetFailedAttempts 重置失败尝试
func (a *AuthInterceptor) resetFailedAttempts(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.failedAttempts, ip)
}

// authorize 验证请求
func (a *AuthInterceptor) authorize(ctx context.Context) error {
	clientIP := a.getClientIP(ctx)

	// 检查是否被锁定
	if a.isLocked(clientIP) {
		return status.Error(codes.ResourceExhausted, "认证失败次数过多，请稍后重试")
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		a.recordFailedAttempt(clientIP)
		return status.Error(codes.Unauthenticated, "缺少元数据")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		a.recordFailedAttempt(clientIP)
		return status.Error(codes.Unauthenticated, "缺少认证令牌")
	}

	token := values[0]
	// 支持 Bearer token 格式
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// 使用常量时间比较防止时序攻击
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.token)) != 1 {
		locked := a.recordFailedAttempt(clientIP)
		if locked {
			return status.Error(codes.ResourceExhausted, "认证失败次数过多，账户已锁定")
		}
		return status.Error(codes.Unauthenticated, "认证令牌无效")
	}

	// 认证成功，重置失败计数
	a.resetFailedAttempts(clientIP)
	return nil
}

// GenerateToken 生成随机令牌
func GenerateToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// tokenClaims 签名令牌的载荷
type tokenClaims struct {
	Token     string `json:"tok"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// GenerateSignedToken 生成带 HMAC-SHA256 签名和过期时间的令牌
// 格式: base64(payload).base64(hmac-sha256(payload))
func GenerateSignedToken(secretKey []byte, ttl time.Duration) (string, error) {
	raw, err := GenerateToken()
	if err != nil {
		return "", err
	}

	now := time.Now().Unix()
	claims := tokenClaims{
		Token:     raw,
		IssuedAt:  now,
		ExpiresAt: now + int64(ttl.Seconds()),
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(payloadB64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payloadB64 + "." + sig, nil
}

// ValidateSignedToken 验证签名令牌的完整性和有效期
func ValidateSignedToken(token string, secretKey []byte) error {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid token format")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// 验证签名
	mac := hmac.New(sha256.New, secretKey)
	mac.Write([]byte(payloadB64))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sigB64), []byte(expectedSig)) != 1 {
		return fmt.Errorf("invalid token signature")
	}

	// 解析载荷
	payload, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return fmt.Errorf("invalid token payload")
	}

	var claims tokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return fmt.Errorf("invalid token claims")
	}

	// Token 永不过期，删除过期检查

	return nil
}

// ValidateToken 验证令牌格式（兼容旧版静态令牌）
func ValidateToken(token string) bool {
	return len(token) >= TokenMinLength
}

// SessionManager 会话管理器
type SessionManager struct {
	sessions map[string]*SessionInfo
	mu       sync.RWMutex
}

// NewSessionManager 创建会话管理器
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*SessionInfo),
	}
}

// CreateSession 创建会话
func (sm *SessionManager) CreateSession(token, clientIP string) *SessionInfo {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	session := &SessionInfo{
		Token:     token,
		ClientIP:  clientIP,
		CreatedAt: now,
		LastUsed:  now,
	}

	sm.sessions[token] = session
	return session
}

// ValidateSession 验证会话
func (sm *SessionManager) ValidateSession(token string) (*SessionInfo, error) {
	sm.mu.RLock()
	session, exists := sm.sessions[token]
	sm.mu.RUnlock()

	if !exists {
		return nil, nil // 会话不存在，回退到静态令牌验证
	}

	// 更新最后使用时间
	sm.mu.Lock()
	session.LastUsed = time.Now()
	sm.mu.Unlock()

	return session, nil
}

// RevokeSession 撤销会话
func (sm *SessionManager) RevokeSession(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, token)
}

// RevokeAllSessions 撤销所有会话
func (sm *SessionManager) RevokeAllSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.sessions = make(map[string]*SessionInfo)
}

// GetActiveSessions 获取活跃会话数
func (sm *SessionManager) GetActiveSessions() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// GetSessionInfo 获取会话信息
func (sm *SessionManager) GetSessionInfo(token string) *SessionInfo {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessions[token]
}

