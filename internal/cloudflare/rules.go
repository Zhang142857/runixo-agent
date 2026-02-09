// Package cloudflare 规则管理
package cloudflare

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SecurityRule 安全规则
type SecurityRule struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        RuleType   `json:"type"`
	Enabled     bool       `json:"enabled"`
	Priority    int        `json:"priority"`
	Conditions  []RuleCond `json:"conditions"`
	Action      RuleAction `json:"action"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// RuleType 规则类型
type RuleType string

const (
	RuleTypeAutoBlock   RuleType = "auto_block"   // 自动封禁规则
	RuleTypeRateLimit   RuleType = "rate_limit"   // 速率限制规则
	RuleTypeGeoBlock    RuleType = "geo_block"    // 地理位置封禁
	RuleTypeUserAgent   RuleType = "user_agent"   // User-Agent 过滤
	RuleTypeCustom      RuleType = "custom"       // 自定义规则
)

// RuleCond 规则条件
type RuleCond struct {
	Field    string `json:"field"`    // ip, path, user_agent, country, etc.
	Operator string `json:"operator"` // eq, ne, contains, matches, gt, lt
	Value    string `json:"value"`
}

// RuleAction 规则动作
type RuleAction struct {
	Type     string `json:"type"`     // block, challenge, js_challenge, allow, log
	Duration int    `json:"duration"` // 封禁时长（秒），0 表示永久
	Message  string `json:"message"`  // 自定义消息
}

// RuleTemplate 规则模板
type RuleTemplate struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Category    string       `json:"category"`
	Rule        SecurityRule `json:"rule"`
}

// RuleManager 规则管理器
type RuleManager struct {
	rules     map[string]*SecurityRule
	templates map[string]*RuleTemplate
	dataPath  string
	mu        sync.RWMutex
}

// NewRuleManager 创建规则管理器
func NewRuleManager(dataPath string) *RuleManager {
	if dataPath == "" {
		dataPath = "/var/lib/runixo/cloudflare"
	}

	rm := &RuleManager{
		rules:     make(map[string]*SecurityRule),
		templates: make(map[string]*RuleTemplate),
		dataPath:  dataPath,
	}

	rm.initTemplates()
	rm.loadRules()

	return rm
}

// initTemplates 初始化规则模板
func (rm *RuleManager) initTemplates() {
	rm.templates = map[string]*RuleTemplate{
		"ssh_brute_force": {
			ID:          "ssh_brute_force",
			Name:        "SSH 暴力破解防护",
			Description: "检测并封禁 SSH 暴力破解尝试",
			Category:    "brute_force",
			Rule: SecurityRule{
				Name:        "SSH 暴力破解防护",
				Description: "5分钟内5次失败登录尝试将被封禁1小时",
				Type:        RuleTypeAutoBlock,
				Enabled:     true,
				Priority:    100,
				Conditions: []RuleCond{
					{Field: "threat_type", Operator: "eq", Value: "brute_force"},
					{Field: "score", Operator: "gte", Value: "100"},
				},
				Action: RuleAction{
					Type:     "block",
					Duration: 3600,
					Message:  "SSH brute force detected",
				},
			},
		},
		"web_scanner": {
			ID:          "web_scanner",
			Name:        "Web 扫描器防护",
			Description: "检测并封禁恶意 Web 扫描器",
			Category:    "scanning",
			Rule: SecurityRule{
				Name:        "Web 扫描器防护",
				Description: "检测到扫描行为将被封禁",
				Type:        RuleTypeAutoBlock,
				Enabled:     true,
				Priority:    90,
				Conditions: []RuleCond{
					{Field: "threat_type", Operator: "eq", Value: "scanning"},
					{Field: "score", Operator: "gte", Value: "50"},
				},
				Action: RuleAction{
					Type:     "block",
					Duration: 1800,
					Message:  "Web scanning detected",
				},
			},
		},
		"sql_injection": {
			ID:          "sql_injection",
			Name:        "SQL 注入防护",
			Description: "检测并封禁 SQL 注入尝试",
			Category:    "injection",
			Rule: SecurityRule{
				Name:        "SQL 注入防护",
				Description: "检测到 SQL 注入尝试将被立即封禁",
				Type:        RuleTypeAutoBlock,
				Enabled:     true,
				Priority:    100,
				Conditions: []RuleCond{
					{Field: "threat_type", Operator: "eq", Value: "sql_injection"},
				},
				Action: RuleAction{
					Type:     "block",
					Duration: 86400, // 24 小时
					Message:  "SQL injection attempt detected",
				},
			},
		},
		"xss_attack": {
			ID:          "xss_attack",
			Name:        "XSS 攻击防护",
			Description: "检测并封禁 XSS 攻击尝试",
			Category:    "injection",
			Rule: SecurityRule{
				Name:        "XSS 攻击防护",
				Description: "检测到 XSS 攻击尝试将被封禁",
				Type:        RuleTypeAutoBlock,
				Enabled:     true,
				Priority:    95,
				Conditions: []RuleCond{
					{Field: "threat_type", Operator: "eq", Value: "xss"},
				},
				Action: RuleAction{
					Type:     "block",
					Duration: 43200, // 12 小时
					Message:  "XSS attack attempt detected",
				},
			},
		},
		"path_traversal": {
			ID:          "path_traversal",
			Name:        "路径遍历防护",
			Description: "检测并封禁路径遍历攻击",
			Category:    "injection",
			Rule: SecurityRule{
				Name:        "路径遍历防护",
				Description: "检测到路径遍历攻击将被封禁",
				Type:        RuleTypeAutoBlock,
				Enabled:     true,
				Priority:    95,
				Conditions: []RuleCond{
					{Field: "threat_type", Operator: "eq", Value: "path_traversal"},
				},
				Action: RuleAction{
					Type:     "block",
					Duration: 43200,
					Message:  "Path traversal attempt detected",
				},
			},
		},
		"malicious_bot": {
			ID:          "malicious_bot",
			Name:        "恶意爬虫防护",
			Description: "检测并封禁恶意爬虫和扫描工具",
			Category:    "bot",
			Rule: SecurityRule{
				Name:        "恶意爬虫防护",
				Description: "检测到恶意爬虫将被封禁",
				Type:        RuleTypeAutoBlock,
				Enabled:     true,
				Priority:    80,
				Conditions: []RuleCond{
					{Field: "threat_type", Operator: "eq", Value: "bot_abuse"},
				},
				Action: RuleAction{
					Type:     "block",
					Duration: 86400,
					Message:  "Malicious bot detected",
				},
			},
		},
		"rate_limit_general": {
			ID:          "rate_limit_general",
			Name:        "通用速率限制",
			Description: "限制单个 IP 的请求频率",
			Category:    "rate_limit",
			Rule: SecurityRule{
				Name:        "通用速率限制",
				Description: "单个 IP 每分钟最多 100 次请求",
				Type:        RuleTypeRateLimit,
				Enabled:     false,
				Priority:    50,
				Conditions: []RuleCond{
					{Field: "requests_per_minute", Operator: "gt", Value: "100"},
				},
				Action: RuleAction{
					Type:     "challenge",
					Duration: 300,
					Message:  "Rate limit exceeded",
				},
			},
		},
	}
}

// GetTemplates 获取所有规则模板
func (rm *RuleManager) GetTemplates() []*RuleTemplate {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	templates := make([]*RuleTemplate, 0, len(rm.templates))
	for _, t := range rm.templates {
		templates = append(templates, t)
	}
	return templates
}

// GetTemplate 获取指定模板
func (rm *RuleManager) GetTemplate(id string) *RuleTemplate {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.templates[id]
}

// CreateRuleFromTemplate 从模板创建规则
func (rm *RuleManager) CreateRuleFromTemplate(templateID string) (*SecurityRule, error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	template, exists := rm.templates[templateID]
	if !exists {
		return nil, nil
	}

	rule := template.Rule
	rule.ID = generateRuleID()
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	rm.rules[rule.ID] = &rule
	rm.saveRules()

	return &rule, nil
}

// CreateRule 创建自定义规则
func (rm *RuleManager) CreateRule(rule *SecurityRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rule.ID == "" {
		rule.ID = generateRuleID()
	}
	rule.CreatedAt = time.Now()
	rule.UpdatedAt = time.Now()

	rm.rules[rule.ID] = rule
	rm.saveRules()

	log.Info().Str("id", rule.ID).Str("name", rule.Name).Msg("规则已创建")
	return nil
}

// UpdateRule 更新规则
func (rm *RuleManager) UpdateRule(rule *SecurityRule) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.rules[rule.ID]; !exists {
		return nil
	}

	rule.UpdatedAt = time.Now()
	rm.rules[rule.ID] = rule
	rm.saveRules()

	log.Info().Str("id", rule.ID).Str("name", rule.Name).Msg("规则已更新")
	return nil
}

// DeleteRule 删除规则
func (rm *RuleManager) DeleteRule(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if _, exists := rm.rules[id]; !exists {
		return nil
	}

	delete(rm.rules, id)
	rm.saveRules()

	log.Info().Str("id", id).Msg("规则已删除")
	return nil
}

// GetRule 获取规则
func (rm *RuleManager) GetRule(id string) *SecurityRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.rules[id]
}

// GetRules 获取所有规则
func (rm *RuleManager) GetRules() []*SecurityRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	rules := make([]*SecurityRule, 0, len(rm.rules))
	for _, r := range rm.rules {
		rules = append(rules, r)
	}
	return rules
}

// GetEnabledRules 获取启用的规则
func (rm *RuleManager) GetEnabledRules() []*SecurityRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var rules []*SecurityRule
	for _, r := range rm.rules {
		if r.Enabled {
			rules = append(rules, r)
		}
	}
	return rules
}

// EnableRule 启用规则
func (rm *RuleManager) EnableRule(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rule, exists := rm.rules[id]; exists {
		rule.Enabled = true
		rule.UpdatedAt = time.Now()
		rm.saveRules()
	}
	return nil
}

// DisableRule 禁用规则
func (rm *RuleManager) DisableRule(id string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rule, exists := rm.rules[id]; exists {
		rule.Enabled = false
		rule.UpdatedAt = time.Now()
		rm.saveRules()
	}
	return nil
}

// MatchThreat 检查威胁是否匹配规则
func (rm *RuleManager) MatchThreat(threat *Threat) *SecurityRule {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var matchedRule *SecurityRule
	highestPriority := -1

	for _, rule := range rm.rules {
		if !rule.Enabled {
			continue
		}

		if rm.matchConditions(rule.Conditions, threat) {
			if rule.Priority > highestPriority {
				matchedRule = rule
				highestPriority = rule.Priority
			}
		}
	}

	return matchedRule
}

// matchConditions 检查条件是否匹配
func (rm *RuleManager) matchConditions(conditions []RuleCond, threat *Threat) bool {
	for _, cond := range conditions {
		if !rm.matchCondition(cond, threat) {
			return false
		}
	}
	return true
}

// matchCondition 检查单个条件
func (rm *RuleManager) matchCondition(cond RuleCond, threat *Threat) bool {
	var fieldValue string

	switch cond.Field {
	case "threat_type":
		fieldValue = string(threat.Type)
	case "ip":
		fieldValue = threat.IP
	case "score":
		// 数值比较
		return rm.compareNumeric(threat.Score, cond.Operator, cond.Value)
	default:
		return false
	}

	return rm.compareString(fieldValue, cond.Operator, cond.Value)
}

// compareString 字符串比较
func (rm *RuleManager) compareString(value, operator, target string) bool {
	switch operator {
	case "eq":
		return value == target
	case "ne":
		return value != target
	case "contains":
		return len(value) >= len(target) && containsString(value, target)
	default:
		return false
	}
}

// compareNumeric 数值比较
func (rm *RuleManager) compareNumeric(value int, operator, target string) bool {
	var targetInt int
	if err := json.Unmarshal([]byte(target), &targetInt); err != nil {
		return false
	}

	switch operator {
	case "eq":
		return value == targetInt
	case "ne":
		return value != targetInt
	case "gt":
		return value > targetInt
	case "gte":
		return value >= targetInt
	case "lt":
		return value < targetInt
	case "lte":
		return value <= targetInt
	default:
		return false
	}
}

// loadRules 从文件加载规则
func (rm *RuleManager) loadRules() {
	filePath := filepath.Join(rm.dataPath, "security_rules.json")

	data, err := os.ReadFile(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Error().Err(err).Msg("加载安全规则失败")
		}
		// 如果没有保存的规则，从模板创建默认规则
		rm.initDefaultRules()
		return
	}

	var rules map[string]*SecurityRule
	if err := json.Unmarshal(data, &rules); err != nil {
		log.Error().Err(err).Msg("解析安全规则失败")
		rm.initDefaultRules()
		return
	}

	rm.rules = rules
	log.Info().Int("count", len(rules)).Msg("已加载安全规则")
}

// initDefaultRules 初始化默认规则
func (rm *RuleManager) initDefaultRules() {
	// 从模板创建默认启用的规则
	defaultTemplates := []string{
		"ssh_brute_force",
		"web_scanner",
		"sql_injection",
		"xss_attack",
		"path_traversal",
		"malicious_bot",
	}

	for _, templateID := range defaultTemplates {
		if template, exists := rm.templates[templateID]; exists {
			rule := template.Rule
			rule.ID = generateRuleID()
			rule.CreatedAt = time.Now()
			rule.UpdatedAt = time.Now()
			rm.rules[rule.ID] = &rule
		}
	}

	rm.saveRules()
	log.Info().Int("count", len(rm.rules)).Msg("已初始化默认安全规则")
}

// saveRules 保存规则到文件
func (rm *RuleManager) saveRules() {
	if err := os.MkdirAll(rm.dataPath, 0755); err != nil {
		log.Error().Err(err).Msg("创建数据目录失败")
		return
	}

	filePath := filepath.Join(rm.dataPath, "security_rules.json")

	data, err := json.MarshalIndent(rm.rules, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("序列化安全规则失败")
		return
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		log.Error().Err(err).Msg("保存安全规则失败")
	}
}

// GetStats 获取规则统计
func (rm *RuleManager) GetStats() map[string]interface{} {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	stats := map[string]interface{}{
		"total_rules":    len(rm.rules),
		"enabled_rules":  0,
		"disabled_rules": 0,
		"by_type":        make(map[string]int),
	}

	byType := stats["by_type"].(map[string]int)

	for _, rule := range rm.rules {
		if rule.Enabled {
			stats["enabled_rules"] = stats["enabled_rules"].(int) + 1
		} else {
			stats["disabled_rules"] = stats["disabled_rules"].(int) + 1
		}
		byType[string(rule.Type)]++
	}

	return stats
}

// generateRuleID 生成规则 ID
func generateRuleID() string {
	return "rule-" + time.Now().Format("20060102150405") + "-" + randomString(6)
}

// containsString 检查字符串是否包含子串
func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
