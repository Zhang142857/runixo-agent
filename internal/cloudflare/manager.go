// Package cloudflare 安全管理器 - 整合所有安全模块
package cloudflare

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SecurityManager 安全管理器
type SecurityManager struct {
	client      *Client
	watcher     *LogWatcher
	detector    *ThreatDetector
	blocker     *IPBlocker
	ruleManager *RuleManager
	config      *SecurityConfig
	mu          sync.RWMutex
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
	eventChan   chan *SecurityEvent
}

// SecurityConfig 安全配置
type SecurityConfig struct {
	// Cloudflare 配置
	Cloudflare *Config `json:"cloudflare"`
	// 监控器配置
	Watcher *WatcherConfig `json:"watcher"`
	// 检测器配置
	Detector *DetectorConfig `json:"detector"`
	// 封禁器配置
	Blocker *BlockerConfig `json:"blocker"`
	// 数据存储路径
	DataPath string `json:"data_path"`
}

// SecurityEvent 安全事件
type SecurityEvent struct {
	Type      string      `json:"type"`
	Timestamp time.Time   `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// SecurityStatus 安全状态
type SecurityStatus struct {
	Running          bool                   `json:"running"`
	CloudflareOK     bool                   `json:"cloudflare_ok"`
	WatcherRunning   bool                   `json:"watcher_running"`
	MonitoredPaths   []string               `json:"monitored_paths"`
	TotalBlocked     int                    `json:"total_blocked"`
	TotalThreats     int                    `json:"total_threats"`
	HighRiskIPs      int                    `json:"high_risk_ips"`
	EnabledRules     int                    `json:"enabled_rules"`
	LastThreat       *Threat                `json:"last_threat,omitempty"`
	Stats            map[string]interface{} `json:"stats"`
}

// DefaultSecurityConfig 默认安全配置
func DefaultSecurityConfig() *SecurityConfig {
	return &SecurityConfig{
		Cloudflare: &Config{},
		Watcher:    DefaultWatcherConfig(),
		Detector:   DefaultDetectorConfig(),
		Blocker:    DefaultBlockerConfig(),
		DataPath:   "/var/lib/runixo/cloudflare",
	}
}

// NewSecurityManager 创建安全管理器
func NewSecurityManager(config *SecurityConfig) (*SecurityManager, error) {
	if config == nil {
		config = DefaultSecurityConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	sm := &SecurityManager{
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		eventChan: make(chan *SecurityEvent, 100),
	}

	// 加载保存的配置
	sm.loadConfig()

	return sm, nil
}

// Configure 配置 Cloudflare
func (sm *SecurityManager) Configure(apiToken, accountID string) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.config.Cloudflare = &Config{
		APIToken:  apiToken,
		AccountID: accountID,
	}

	// 创建客户端
	sm.client = NewClient(sm.config.Cloudflare)

	// 验证 Token
	valid, err := sm.client.VerifyToken()
	if err != nil {
		return err
	}
	if !valid {
		return &ConfigError{Message: "API Token 无效"}
	}

	// 保存配置
	sm.saveConfig()

	log.Info().Msg("Cloudflare 配置已更新")
	return nil
}

// Start 启动安全管理器
func (sm *SecurityManager) Start() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if sm.running {
		return nil
	}

	if sm.client == nil {
		if sm.config.Cloudflare == nil || sm.config.Cloudflare.APIToken == "" {
			return &ConfigError{Message: "Cloudflare 未配置"}
		}
		sm.client = NewClient(sm.config.Cloudflare)
	}

	// 初始化各模块
	sm.detector = NewThreatDetector(sm.config.Detector)
	sm.blocker = NewIPBlocker(sm.client, sm.config.Blocker)
	sm.ruleManager = NewRuleManager(sm.config.DataPath)

	// 创建日志监控器
	var err error
	sm.watcher, err = NewLogWatcher(sm.config.Watcher, sm.detector, sm.blocker)
	if err != nil {
		return err
	}

	// 启动监控
	if err := sm.watcher.Start(); err != nil {
		return err
	}

	// 启动事件处理
	go sm.processEvents()

	sm.running = true
	log.Info().Msg("安全管理器已启动")

	return nil
}

// Stop 停止安全管理器
func (sm *SecurityManager) Stop() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if !sm.running {
		return
	}

	if sm.watcher != nil {
		sm.watcher.Stop()
	}

	if sm.blocker != nil {
		sm.blocker.Stop()
	}

	sm.cancel()
	sm.running = false

	log.Info().Msg("安全管理器已停止")
}

// GetStatus 获取安全状态
func (sm *SecurityManager) GetStatus() *SecurityStatus {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	status := &SecurityStatus{
		Running:      sm.running,
		CloudflareOK: sm.client != nil,
		Stats:        make(map[string]interface{}),
	}

	if sm.watcher != nil {
		status.WatcherRunning = sm.watcher.IsRunning()
		status.MonitoredPaths = sm.watcher.GetPaths()
	}

	if sm.blocker != nil {
		blocked := sm.blocker.GetBlockedIPs()
		status.TotalBlocked = len(blocked)
		status.Stats["blocker"] = sm.blocker.GetStats()
	}

	if sm.detector != nil {
		activities := sm.detector.GetAllActivities()
		status.TotalThreats = len(activities)
		highRisk := sm.detector.GetHighRiskIPs(50)
		status.HighRiskIPs = len(highRisk)
	}

	if sm.ruleManager != nil {
		enabled := sm.ruleManager.GetEnabledRules()
		status.EnabledRules = len(enabled)
		status.Stats["rules"] = sm.ruleManager.GetStats()
	}

	return status
}

// GetBlockedIPs 获取已封禁的 IP 列表
func (sm *SecurityManager) GetBlockedIPs() []*BlockedIP {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.blocker == nil {
		return nil
	}

	return sm.blocker.GetBlockedIPs()
}

// BlockIP 手动封禁 IP
func (sm *SecurityManager) BlockIP(ip, zoneID, reason string, duration int) (*BlockedIP, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.blocker == nil {
		return nil, &ConfigError{Message: "封禁器未初始化"}
	}

	return sm.blocker.ManualBlock(ip, zoneID, reason, duration)
}

// UnblockIP 解封 IP
func (sm *SecurityManager) UnblockIP(ip, zoneID string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.blocker == nil {
		return &ConfigError{Message: "封禁器未初始化"}
	}

	return sm.blocker.Unblock(ip, zoneID)
}

// GetThreats 获取威胁列表
func (sm *SecurityManager) GetThreats() []*IPActivity {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.detector == nil {
		return nil
	}

	return sm.detector.GetAllActivities()
}

// GetHighRiskIPs 获取高风险 IP
func (sm *SecurityManager) GetHighRiskIPs(minScore int) []*IPActivity {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.detector == nil {
		return nil
	}

	return sm.detector.GetHighRiskIPs(minScore)
}

// GetRules 获取安全规则
func (sm *SecurityManager) GetRules() []*SecurityRule {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ruleManager == nil {
		return nil
	}

	return sm.ruleManager.GetRules()
}

// GetRuleTemplates 获取规则模板
func (sm *SecurityManager) GetRuleTemplates() []*RuleTemplate {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ruleManager == nil {
		return nil
	}

	return sm.ruleManager.GetTemplates()
}

// CreateRule 创建规则
func (sm *SecurityManager) CreateRule(rule *SecurityRule) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ruleManager == nil {
		return &ConfigError{Message: "规则管理器未初始化"}
	}

	return sm.ruleManager.CreateRule(rule)
}

// EnableRule 启用规则
func (sm *SecurityManager) EnableRule(id string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ruleManager == nil {
		return &ConfigError{Message: "规则管理器未初始化"}
	}

	return sm.ruleManager.EnableRule(id)
}

// DisableRule 禁用规则
func (sm *SecurityManager) DisableRule(id string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ruleManager == nil {
		return &ConfigError{Message: "规则管理器未初始化"}
	}

	return sm.ruleManager.DisableRule(id)
}

// DeleteRule 删除规则
func (sm *SecurityManager) DeleteRule(id string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.ruleManager == nil {
		return &ConfigError{Message: "规则管理器未初始化"}
	}

	return sm.ruleManager.DeleteRule(id)
}

// GetZones 获取域名列表
func (sm *SecurityManager) GetZones() ([]Zone, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.client == nil {
		return nil, &ConfigError{Message: "Cloudflare 未配置"}
	}

	return sm.client.ListZones()
}

// EnableUnderAttackMode 启用 Under Attack 模式
func (sm *SecurityManager) EnableUnderAttackMode(zoneID string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.client == nil {
		return &ConfigError{Message: "Cloudflare 未配置"}
	}

	return sm.client.EnableUnderAttackMode(zoneID)
}

// DisableUnderAttackMode 禁用 Under Attack 模式
func (sm *SecurityManager) DisableUnderAttackMode(zoneID string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.client == nil {
		return &ConfigError{Message: "Cloudflare 未配置"}
	}

	return sm.client.DisableUnderAttackMode(zoneID)
}

// AddMonitorPath 添加监控路径
func (sm *SecurityManager) AddMonitorPath(path string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.watcher == nil {
		return &ConfigError{Message: "监控器未初始化"}
	}

	return sm.watcher.AddPath(path)
}

// RemoveMonitorPath 移除监控路径
func (sm *SecurityManager) RemoveMonitorPath(path string) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if sm.watcher != nil {
		sm.watcher.RemovePath(path)
	}
}

// Events 返回事件通道
func (sm *SecurityManager) Events() <-chan *SecurityEvent {
	return sm.eventChan
}

// processEvents 处理事件
func (sm *SecurityManager) processEvents() {
	for {
		select {
		case <-sm.ctx.Done():
			return

		case threat, ok := <-sm.detector.Threats():
			if !ok {
				continue
			}
			sm.sendEvent("threat", threat)

		case event, ok := <-sm.blocker.Events():
			if !ok {
				continue
			}
			sm.sendEvent("block", event)
		}
	}
}

// sendEvent 发送事件
func (sm *SecurityManager) sendEvent(eventType string, data interface{}) {
	event := &SecurityEvent{
		Type:      eventType,
		Timestamp: time.Now(),
		Data:      data,
	}

	select {
	case sm.eventChan <- event:
	default:
		log.Warn().Str("type", eventType).Msg("安全事件通道已满")
	}
}

// loadConfig 加载配置
func (sm *SecurityManager) loadConfig() {
	filePath := filepath.Join(sm.config.DataPath, "security_config.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error().Err(err).Msg("加载安全配置失败")
		}
		return
	}

	var config SecurityConfig
	if err := json.Unmarshal(data, &config); err != nil {
		log.Error().Err(err).Msg("解析安全配置失败")
		return
	}

	// 合并配置（保留敏感信息）
	if config.Cloudflare != nil && config.Cloudflare.APIToken != "" {
		sm.config.Cloudflare = config.Cloudflare
	}
	if config.Watcher != nil {
		sm.config.Watcher = config.Watcher
	}
	if config.Detector != nil {
		sm.config.Detector = config.Detector
	}
	if config.Blocker != nil {
		sm.config.Blocker = config.Blocker
	}

	log.Info().Msg("已加载安全配置")
}

// saveConfig 保存配置
func (sm *SecurityManager) saveConfig() {
	if err := os.MkdirAll(sm.config.DataPath, 0755); err != nil {
		log.Error().Err(err).Msg("创建数据目录失败")
		return
	}

	filePath := filepath.Join(sm.config.DataPath, "security_config.json")

	// 不保存敏感信息到文件
	configToSave := &SecurityConfig{
		Cloudflare: &Config{
			AccountID: sm.config.Cloudflare.AccountID,
			// APIToken 不保存
		},
		Watcher:  sm.config.Watcher,
		Detector: sm.config.Detector,
		Blocker:  sm.config.Blocker,
		DataPath: sm.config.DataPath,
	}

	data, err := json.MarshalIndent(configToSave, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("序列化安全配置失败")
		return
	}

	if err := os.WriteFile(filePath, data, 0600); err != nil {
		log.Error().Err(err).Msg("保存安全配置失败")
	}
}

// UpdateConfig 更新配置
func (sm *SecurityManager) UpdateConfig(config *SecurityConfig) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	if config.Watcher != nil {
		sm.config.Watcher = config.Watcher
	}
	if config.Detector != nil {
		sm.config.Detector = config.Detector
	}
	if config.Blocker != nil {
		sm.config.Blocker = config.Blocker
	}

	sm.saveConfig()
	return nil
}

// GetConfig 获取当前配置
func (sm *SecurityManager) GetConfig() *SecurityConfig {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	// 返回副本，隐藏敏感信息
	return &SecurityConfig{
		Cloudflare: &Config{
			AccountID: sm.config.Cloudflare.AccountID,
		},
		Watcher:  sm.config.Watcher,
		Detector: sm.config.Detector,
		Blocker:  sm.config.Blocker,
		DataPath: sm.config.DataPath,
	}
}

// ConfigError 配置错误
type ConfigError struct {
	Message string
}

func (e *ConfigError) Error() string {
	return e.Message
}

// IsConfigured 检查是否已配置
func (sm *SecurityManager) IsConfigured() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return sm.config.Cloudflare != nil && sm.config.Cloudflare.APIToken != ""
}

// IsRunning 检查是否正在运行
func (sm *SecurityManager) IsRunning() bool {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.running
}
