// Package plugin 插件实例实现
package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/runixo/agent/internal/cloudflare"
)

// GenericPlugin 通用插件实现
type GenericPlugin struct {
	pluginsDir string
	pluginID   string
	config     map[string]any
	running    bool
	mu         sync.RWMutex
}

// NewGenericPlugin 创建通用插件
func NewGenericPlugin(pluginsDir, pluginID string) (*GenericPlugin, error) {
	return &GenericPlugin{
		pluginsDir: pluginsDir,
		pluginID:   pluginID,
	}, nil
}

// Start 启动插件
func (p *GenericPlugin) Start(ctx context.Context, config map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.config = config
	p.running = true

	log.Info().Str("plugin", p.pluginID).Msg("通用插件已启动")
	return nil
}

// Stop 停止插件
func (p *GenericPlugin) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.running = false
	log.Info().Str("plugin", p.pluginID).Msg("通用插件已停止")
	return nil
}

// GetStatus 获取状态
func (p *GenericPlugin) GetStatus() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	return map[string]string{
		"running": fmt.Sprintf("%v", p.running),
	}
}

// CloudflarePlugin Cloudflare 安全插件
type CloudflarePlugin struct {
	pluginsDir string
	pluginID   string
	manager    *cloudflare.SecurityManager
	config     *CloudflareConfig
	running    bool
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
}

// CloudflareConfig Cloudflare 插件配置
type CloudflareConfig struct {
	APIToken       string   `json:"api_token"`
	AccountID      string   `json:"account_id"`
	AutoBlock      bool     `json:"auto_block"`
	BlockThreshold int      `json:"block_threshold"`
	BlockDuration  int      `json:"block_duration"`
	MonitorPaths   []string `json:"monitor_paths"`
	Enabled        bool     `json:"enabled"`
}

// NewCloudflarePlugin 创建 Cloudflare 插件
func NewCloudflarePlugin(pluginsDir, pluginID string) (*CloudflarePlugin, error) {
	return &CloudflarePlugin{
		pluginsDir: pluginsDir,
		pluginID:   pluginID,
	}, nil
}

// Start 启动 Cloudflare 插件
func (p *CloudflarePlugin) Start(ctx context.Context, config map[string]any) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// 解析配置
	configData, err := json.Marshal(config)
	if err != nil {
		return fmt.Errorf("序列化配置失败: %w", err)
	}

	var cfConfig CloudflareConfig
	if err := json.Unmarshal(configData, &cfConfig); err != nil {
		return fmt.Errorf("解析配置失败: %w", err)
	}
	p.config = &cfConfig

	if !cfConfig.Enabled {
		log.Info().Str("plugin", p.pluginID).Msg("Cloudflare 插件未启用")
		return nil
	}

	if cfConfig.APIToken == "" {
		return fmt.Errorf("API Token 未配置")
	}

	// 创建安全管理器
	secConfig := cloudflare.DefaultSecurityConfig()
	secConfig.DataPath = filepath.Join(p.pluginsDir, p.pluginID, "data")

	if cfConfig.BlockThreshold > 0 {
		secConfig.Detector.BlockThreshold = cfConfig.BlockThreshold
	}
	if cfConfig.BlockDuration > 0 {
		secConfig.Blocker.DefaultBlockDuration = cfConfig.BlockDuration
	}
	secConfig.Blocker.AutoBlockEnabled = cfConfig.AutoBlock

	manager, err := cloudflare.NewSecurityManager(secConfig)
	if err != nil {
		return fmt.Errorf("创建安全管理器失败: %w", err)
	}

	// 配置 Cloudflare
	if err := manager.Configure(cfConfig.APIToken, cfConfig.AccountID); err != nil {
		return fmt.Errorf("配置 Cloudflare 失败: %w", err)
	}

	// 启动安全管理器
	if err := manager.Start(); err != nil {
		return fmt.Errorf("启动安全管理器失败: %w", err)
	}

	// 添加监控路径
	for _, path := range cfConfig.MonitorPaths {
		if err := manager.AddMonitorPath(path); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("添加监控路径失败")
		}
	}

	p.manager = manager
	p.ctx, p.cancel = context.WithCancel(ctx)
	p.running = true

	// 启动事件处理
	go p.processEvents()

	log.Info().Str("plugin", p.pluginID).Msg("Cloudflare 安全插件已启动")
	return nil
}

// Stop 停止 Cloudflare 插件
func (p *CloudflarePlugin) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.cancel != nil {
		p.cancel()
	}

	if p.manager != nil {
		p.manager.Stop()
	}

	p.running = false
	log.Info().Str("plugin", p.pluginID).Msg("Cloudflare 安全插件已停止")
	return nil
}

// GetStatus 获取状态
func (p *CloudflarePlugin) GetStatus() map[string]string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	status := map[string]string{
		"running": fmt.Sprintf("%v", p.running),
	}

	if p.manager != nil {
		secStatus := p.manager.GetStatus()
		status["cloudflare_ok"] = fmt.Sprintf("%v", secStatus.CloudflareOK)
		status["watcher_running"] = fmt.Sprintf("%v", secStatus.WatcherRunning)
		status["total_blocked"] = fmt.Sprintf("%d", secStatus.TotalBlocked)
		status["total_threats"] = fmt.Sprintf("%d", secStatus.TotalThreats)
		status["high_risk_ips"] = fmt.Sprintf("%d", secStatus.HighRiskIPs)
	}

	return status
}

// processEvents 处理安全事件
func (p *CloudflarePlugin) processEvents() {
	if p.manager == nil {
		return
	}

	events := p.manager.Events()
	for {
		select {
		case <-p.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			log.Info().
				Str("type", event.Type).
				Time("timestamp", event.Timestamp).
				Msg("安全事件")
		}
	}
}

// GetManager 获取安全管理器（供外部调用）
func (p *CloudflarePlugin) GetManager() *cloudflare.SecurityManager {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.manager
}

// UpdateConfig 更新配置
func (p *CloudflarePlugin) UpdateConfig(config map[string]any) error {
	// 停止当前实例
	if err := p.Stop(); err != nil {
		return err
	}

	// 使用新配置重新启动
	return p.Start(context.Background(), config)
}

// SaveConfig 保存配置到文件
func (p *CloudflarePlugin) SaveConfig() error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.config == nil {
		return nil
	}

	configFile := filepath.Join(p.pluginsDir, p.pluginID, "config.json")
	data, err := json.MarshalIndent(p.config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0644)
}

// LoadConfig 从文件加载配置
func (p *CloudflarePlugin) LoadConfig() error {
	configFile := filepath.Join(p.pluginsDir, p.pluginID, "config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var config CloudflareConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	p.mu.Lock()
	p.config = &config
	p.mu.Unlock()

	return nil
}

// GetBlockedIPs 获取已封禁的 IP
func (p *CloudflarePlugin) GetBlockedIPs() []*cloudflare.BlockedIP {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.manager == nil {
		return nil
	}

	return p.manager.GetBlockedIPs()
}

// BlockIP 手动封禁 IP
func (p *CloudflarePlugin) BlockIP(ip, zoneID, reason string, duration int) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.manager == nil {
		return fmt.Errorf("插件未运行")
	}

	_, err := p.manager.BlockIP(ip, zoneID, reason, duration)
	return err
}

// UnblockIP 解封 IP
func (p *CloudflarePlugin) UnblockIP(ip, zoneID string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.manager == nil {
		return fmt.Errorf("插件未运行")
	}

	return p.manager.UnblockIP(ip, zoneID)
}

// ScheduledTask 定时任务插件基类
type ScheduledTask struct {
	interval time.Duration
	task     func() error
	running  bool
	stopChan chan struct{}
	mu       sync.RWMutex
}

// NewScheduledTask 创建定时任务
func NewScheduledTask(interval time.Duration, task func() error) *ScheduledTask {
	return &ScheduledTask{
		interval: interval,
		task:     task,
		stopChan: make(chan struct{}),
	}
}

// Start 启动定时任务
func (t *ScheduledTask) Start() {
	t.mu.Lock()
	if t.running {
		t.mu.Unlock()
		return
	}
	t.running = true
	t.mu.Unlock()

	go func() {
		ticker := time.NewTicker(t.interval)
		defer ticker.Stop()

		// 立即执行一次
		if err := t.task(); err != nil {
			log.Error().Err(err).Msg("定时任务执行失败")
		}

		for {
			select {
			case <-t.stopChan:
				return
			case <-ticker.C:
				if err := t.task(); err != nil {
					log.Error().Err(err).Msg("定时任务执行失败")
				}
			}
		}
	}()
}

// Stop 停止定时任务
func (t *ScheduledTask) Stop() {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.running {
		return
	}

	close(t.stopChan)
	t.running = false
}

// IsRunning 检查是否运行中
func (t *ScheduledTask) IsRunning() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.running
}
