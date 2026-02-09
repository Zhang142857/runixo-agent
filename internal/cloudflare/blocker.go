// Package cloudflare IP 封禁执行器
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

// BlockedIP 已封禁的 IP 信息
type BlockedIP struct {
	IP          string     `json:"ip"`
	RuleID      string     `json:"rule_id"`
	ZoneID      string     `json:"zone_id"`
	ZoneName    string     `json:"zone_name"`
	Reason      string     `json:"reason"`
	ThreatType  ThreatType `json:"threat_type"`
	Score       int        `json:"score"`
	BlockedAt   time.Time  `json:"blocked_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AutoBlocked bool       `json:"auto_blocked"`
}

// BlockerConfig 封禁器配置
type BlockerConfig struct {
	// 是否启用自动封禁
	AutoBlockEnabled bool `json:"auto_block_enabled"`
	// 默认封禁时长（秒），0 表示永久
	DefaultBlockDuration int `json:"default_block_duration"`
	// 封禁模式：block, challenge, js_challenge
	BlockMode string `json:"block_mode"`
	// 要保护的域名 Zone ID 列表（空表示所有域名）
	ProtectedZones []string `json:"protected_zones"`
	// 白名单 IP
	WhitelistIPs []string `json:"whitelist_ips"`
	// 数据存储路径
	DataPath string `json:"data_path"`
}

// IPBlocker IP 封禁执行器
type IPBlocker struct {
	client     *Client
	config     *BlockerConfig
	blockedIPs map[string]*BlockedIP
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	eventChan  chan *BlockEvent
}

// BlockEvent 封禁事件
type BlockEvent struct {
	Type      string     `json:"type"` // blocked, unblocked, expired
	IP        string     `json:"ip"`
	ZoneID    string     `json:"zone_id"`
	Reason    string     `json:"reason"`
	Timestamp time.Time  `json:"timestamp"`
	Threat    *Threat    `json:"threat,omitempty"`
	BlockedIP *BlockedIP `json:"blocked_ip,omitempty"`
}

// DefaultBlockerConfig 默认封禁器配置
func DefaultBlockerConfig() *BlockerConfig {
	return &BlockerConfig{
		AutoBlockEnabled:     true,
		DefaultBlockDuration: 3600, // 1 小时
		BlockMode:            "block",
		ProtectedZones:       []string{},
		WhitelistIPs:         []string{},
		DataPath:             "/var/lib/runixo/cloudflare",
	}
}

// NewIPBlocker 创建 IP 封禁器
func NewIPBlocker(client *Client, config *BlockerConfig) *IPBlocker {
	if config == nil {
		config = DefaultBlockerConfig()
	}

	ctx, cancel := context.WithCancel(context.Background())

	blocker := &IPBlocker{
		client:     client,
		config:     config,
		blockedIPs: make(map[string]*BlockedIP),
		ctx:        ctx,
		cancel:     cancel,
		eventChan:  make(chan *BlockEvent, 100),
	}

	// 加载已保存的封禁记录
	blocker.loadBlockedIPs()

	// 启动过期检查
	go blocker.expirationLoop()

	return blocker
}

// BlockThreat 封禁威胁 IP
func (b *IPBlocker) BlockThreat(threat *Threat) error {
	if !b.config.AutoBlockEnabled {
		return nil
	}

	// 检查白名单
	if b.isWhitelisted(threat.IP) {
		log.Debug().Str("ip", threat.IP).Msg("IP 在白名单中，跳过封禁")
		return nil
	}

	// 检查是否已封禁
	if b.IsBlocked(threat.IP) {
		log.Debug().Str("ip", threat.IP).Msg("IP 已被封禁")
		return nil
	}

	reason := threat.Description
	if reason == "" {
		reason = "Auto-blocked by Runixo: " + string(threat.Type)
	}

	// 获取要保护的域名
	zones, err := b.getProtectedZones()
	if err != nil {
		log.Error().Err(err).Msg("获取域名列表失败")
		return err
	}

	// 在所有保护的域名上封禁该 IP
	for _, zone := range zones {
		if err := b.blockIPOnZone(threat.IP, zone.ID, zone.Name, reason, threat); err != nil {
			log.Error().Err(err).Str("ip", threat.IP).Str("zone", zone.Name).Msg("封禁 IP 失败")
			continue
		}
	}

	return nil
}

// blockIPOnZone 在指定域名上封禁 IP
func (b *IPBlocker) blockIPOnZone(ip, zoneID, zoneName, reason string, threat *Threat) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 调用 Cloudflare API 封禁
	rule, err := b.client.CreateAccessRule(zoneID, b.config.BlockMode, ip, reason)
	if err != nil {
		return err
	}

	// 计算过期时间
	var expiresAt *time.Time
	if b.config.DefaultBlockDuration > 0 {
		t := time.Now().Add(time.Duration(b.config.DefaultBlockDuration) * time.Second)
		expiresAt = &t
	}

	// 记录封禁信息
	blocked := &BlockedIP{
		IP:          ip,
		RuleID:      rule.ID,
		ZoneID:      zoneID,
		ZoneName:    zoneName,
		Reason:      reason,
		ThreatType:  threat.Type,
		Score:       threat.Score,
		BlockedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		AutoBlocked: true,
	}

	key := ip + ":" + zoneID
	b.blockedIPs[key] = blocked

	// 保存到文件
	b.saveBlockedIPs()

	// 发送事件
	b.sendEvent(&BlockEvent{
		Type:      "blocked",
		IP:        ip,
		ZoneID:    zoneID,
		Reason:    reason,
		Timestamp: time.Now(),
		Threat:    threat,
		BlockedIP: blocked,
	})

	log.Info().
		Str("ip", ip).
		Str("zone", zoneName).
		Str("rule_id", rule.ID).
		Str("threat_type", string(threat.Type)).
		Int("score", threat.Score).
		Msg("IP 已封禁")

	return nil
}

// ManualBlock 手动封禁 IP
func (b *IPBlocker) ManualBlock(ip, zoneID, reason string, durationSeconds int) (*BlockedIP, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// 获取域名信息
	zone, err := b.client.GetZone(zoneID)
	if err != nil {
		return nil, err
	}

	// 调用 Cloudflare API 封禁
	rule, err := b.client.CreateAccessRule(zoneID, b.config.BlockMode, ip, reason)
	if err != nil {
		return nil, err
	}

	// 计算过期时间
	var expiresAt *time.Time
	if durationSeconds > 0 {
		t := time.Now().Add(time.Duration(durationSeconds) * time.Second)
		expiresAt = &t
	}

	// 记录封禁信息
	blocked := &BlockedIP{
		IP:          ip,
		RuleID:      rule.ID,
		ZoneID:      zoneID,
		ZoneName:    zone.Name,
		Reason:      reason,
		ThreatType:  ThreatTypeUnknown,
		Score:       0,
		BlockedAt:   time.Now(),
		ExpiresAt:   expiresAt,
		AutoBlocked: false,
	}

	key := ip + ":" + zoneID
	b.blockedIPs[key] = blocked

	// 保存到文件
	b.saveBlockedIPs()

	// 发送事件
	b.sendEvent(&BlockEvent{
		Type:      "blocked",
		IP:        ip,
		ZoneID:    zoneID,
		Reason:    reason,
		Timestamp: time.Now(),
		BlockedIP: blocked,
	})

	log.Info().
		Str("ip", ip).
		Str("zone", zone.Name).
		Str("rule_id", rule.ID).
		Msg("IP 已手动封禁")

	return blocked, nil
}

// Unblock 解封 IP
func (b *IPBlocker) Unblock(ip, zoneID string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	key := ip + ":" + zoneID
	blocked, exists := b.blockedIPs[key]
	if !exists {
		return nil
	}

	// 调用 Cloudflare API 删除规则
	if err := b.client.DeleteAccessRule(zoneID, blocked.RuleID); err != nil {
		return err
	}

	// 删除记录
	delete(b.blockedIPs, key)

	// 保存到文件
	b.saveBlockedIPs()

	// 发送事件
	b.sendEvent(&BlockEvent{
		Type:      "unblocked",
		IP:        ip,
		ZoneID:    zoneID,
		Reason:    "Manual unblock",
		Timestamp: time.Now(),
		BlockedIP: blocked,
	})

	log.Info().
		Str("ip", ip).
		Str("zone", blocked.ZoneName).
		Msg("IP 已解封")

	return nil
}

// IsBlocked 检查 IP 是否已被封禁
func (b *IPBlocker) IsBlocked(ip string) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()

	for key := range b.blockedIPs {
		if len(key) > len(ip) && key[:len(ip)] == ip && key[len(ip)] == ':' {
			return true
		}
	}
	return false
}

// GetBlockedIPs 获取所有已封禁的 IP
func (b *IPBlocker) GetBlockedIPs() []*BlockedIP {
	b.mu.RLock()
	defer b.mu.RUnlock()

	result := make([]*BlockedIP, 0, len(b.blockedIPs))
	for _, blocked := range b.blockedIPs {
		result = append(result, blocked)
	}
	return result
}

// GetBlockedIPsByZone 获取指定域名的已封禁 IP
func (b *IPBlocker) GetBlockedIPsByZone(zoneID string) []*BlockedIP {
	b.mu.RLock()
	defer b.mu.RUnlock()

	var result []*BlockedIP
	for _, blocked := range b.blockedIPs {
		if blocked.ZoneID == zoneID {
			result = append(result, blocked)
		}
	}
	return result
}

// Events 返回事件通道
func (b *IPBlocker) Events() <-chan *BlockEvent {
	return b.eventChan
}

// Stop 停止封禁器
func (b *IPBlocker) Stop() {
	b.cancel()
	close(b.eventChan)
}

// getProtectedZones 获取要保护的域名列表
func (b *IPBlocker) getProtectedZones() ([]Zone, error) {
	allZones, err := b.client.ListZones()
	if err != nil {
		return nil, err
	}

	// 如果没有指定保护的域名，返回所有域名
	if len(b.config.ProtectedZones) == 0 {
		return allZones, nil
	}

	// 过滤出指定的域名
	var zones []Zone
	for _, zone := range allZones {
		for _, protectedID := range b.config.ProtectedZones {
			if zone.ID == protectedID {
				zones = append(zones, zone)
				break
			}
		}
	}

	return zones, nil
}

// isWhitelisted 检查 IP 是否在白名单中
func (b *IPBlocker) isWhitelisted(ip string) bool {
	for _, whiteIP := range b.config.WhitelistIPs {
		if ip == whiteIP {
			return true
		}
	}
	return false
}

// expirationLoop 过期检查循环
func (b *IPBlocker) expirationLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-b.ctx.Done():
			return
		case <-ticker.C:
			b.checkExpirations()
		}
	}
}

// checkExpirations 检查过期的封禁
func (b *IPBlocker) checkExpirations() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for key, blocked := range b.blockedIPs {
		if blocked.ExpiresAt != nil && blocked.ExpiresAt.Before(now) {
			// 调用 Cloudflare API 删除规则
			if err := b.client.DeleteAccessRule(blocked.ZoneID, blocked.RuleID); err != nil {
				log.Error().Err(err).Str("ip", blocked.IP).Msg("删除过期封禁规则失败")
				continue
			}

			toRemove = append(toRemove, key)

			// 发送事件
			b.sendEvent(&BlockEvent{
				Type:      "expired",
				IP:        blocked.IP,
				ZoneID:    blocked.ZoneID,
				Reason:    "Block expired",
				Timestamp: now,
				BlockedIP: blocked,
			})

			log.Info().
				Str("ip", blocked.IP).
				Str("zone", blocked.ZoneName).
				Msg("封禁已过期，自动解封")
		}
	}

	// 删除过期记录
	for _, key := range toRemove {
		delete(b.blockedIPs, key)
	}

	if len(toRemove) > 0 {
		b.saveBlockedIPs()
	}
}

// sendEvent 发送事件
func (b *IPBlocker) sendEvent(event *BlockEvent) {
	select {
	case b.eventChan <- event:
	default:
		log.Warn().Msg("封禁事件通道已满")
	}
}

// loadBlockedIPs 从文件加载封禁记录
func (b *IPBlocker) loadBlockedIPs() {
	filePath := filepath.Join(b.config.DataPath, "blocked_ips.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error().Err(err).Msg("加载封禁记录失败")
		}
		return
	}

	var blocked map[string]*BlockedIP
	if err := json.Unmarshal(data, &blocked); err != nil {
		log.Error().Err(err).Msg("解析封禁记录失败")
		return
	}

	b.blockedIPs = blocked
	log.Info().Int("count", len(blocked)).Msg("已加载封禁记录")
}

// saveBlockedIPs 保存封禁记录到文件
func (b *IPBlocker) saveBlockedIPs() {
	// 确保目录存在
	if err := os.MkdirAll(b.config.DataPath, 0755); err != nil {
		log.Error().Err(err).Msg("创建数据目录失败")
		return
	}

	filePath := filepath.Join(b.config.DataPath, "blocked_ips.json")

	data, err := json.MarshalIndent(b.blockedIPs, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("序列化封禁记录失败")
		return
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Error().Err(err).Msg("保存封禁记录失败")
	}
}

// SetConfig 更新配置
func (b *IPBlocker) SetConfig(config *BlockerConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.config = config
}

// GetConfig 获取当前配置
func (b *IPBlocker) GetConfig() *BlockerConfig {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.config
}

// AddToWhitelist 添加 IP 到白名单
func (b *IPBlocker) AddToWhitelist(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, whiteIP := range b.config.WhitelistIPs {
		if ip == whiteIP {
			return
		}
	}
	b.config.WhitelistIPs = append(b.config.WhitelistIPs, ip)
}

// RemoveFromWhitelist 从白名单移除 IP
func (b *IPBlocker) RemoveFromWhitelist(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for i, whiteIP := range b.config.WhitelistIPs {
		if ip == whiteIP {
			b.config.WhitelistIPs = append(b.config.WhitelistIPs[:i], b.config.WhitelistIPs[i+1:]...)
			return
		}
	}
}

// GetStats 获取封禁统计
func (b *IPBlocker) GetStats() map[string]interface{} {
	b.mu.RLock()
	defer b.mu.RUnlock()

	stats := map[string]interface{}{
		"total_blocked":      len(b.blockedIPs),
		"auto_blocked":       0,
		"manual_blocked":     0,
		"by_threat_type":     make(map[string]int),
		"by_zone":            make(map[string]int),
		"auto_block_enabled": b.config.AutoBlockEnabled,
	}

	byType := stats["by_threat_type"].(map[string]int)
	byZone := stats["by_zone"].(map[string]int)

	for _, blocked := range b.blockedIPs {
		if blocked.AutoBlocked {
			stats["auto_blocked"] = stats["auto_blocked"].(int) + 1
		} else {
			stats["manual_blocked"] = stats["manual_blocked"].(int) + 1
		}
		byType[string(blocked.ThreatType)]++
		byZone[blocked.ZoneName]++
	}

	return stats
}
