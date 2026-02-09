// Package cloudflare 威胁检测器
package cloudflare

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// ThreatType 威胁类型
type ThreatType string

const (
	ThreatTypeBruteForce    ThreatType = "brute_force"     // 暴力破解
	ThreatTypeScanning      ThreatType = "scanning"        // 端口/漏洞扫描
	ThreatTypeSQLInjection  ThreatType = "sql_injection"   // SQL 注入
	ThreatTypeXSS           ThreatType = "xss"             // XSS 攻击
	ThreatTypePathTraversal ThreatType = "path_traversal"  // 路径遍历
	ThreatTypeBotAbuse      ThreatType = "bot_abuse"       // 恶意爬虫
	ThreatTypeDDoS          ThreatType = "ddos"            // DDoS 攻击
	ThreatTypeUnknown       ThreatType = "unknown"         // 未知威胁
)

// Threat 威胁信息
type Threat struct {
	ID          string     `json:"id"`
	IP          string     `json:"ip"`
	Type        ThreatType `json:"type"`
	Score       int        `json:"score"`
	Description string     `json:"description"`
	Source      string     `json:"source"`
	Line        string     `json:"line"`
	Timestamp   time.Time  `json:"timestamp"`
	Count       int        `json:"count"`
}

// ThreatDetector 威胁检测器
type ThreatDetector struct {
	config     *DetectorConfig
	patterns   []DetectionPattern
	ipTracker  map[string]*IPActivity
	mu         sync.RWMutex
	threatChan chan *Threat
}

// DetectorConfig 检测器配置
type DetectorConfig struct {
	// 封禁阈值分数
	BlockThreshold int `json:"block_threshold"`
	// 时间窗口（秒）
	TimeWindowSeconds int `json:"time_window_seconds"`
	// 是否启用各类检测
	EnableBruteForceDetection bool `json:"enable_brute_force_detection"`
	EnableScanningDetection   bool `json:"enable_scanning_detection"`
	EnableInjectionDetection  bool `json:"enable_injection_detection"`
	EnableBotDetection        bool `json:"enable_bot_detection"`
}

// DetectionPattern 检测模式
type DetectionPattern struct {
	Name        string
	Type        ThreatType
	Pattern     *regexp.Regexp
	Score       int
	Description string
	IPExtractor func(string) string
}

// IPActivity IP 活动记录
type IPActivity struct {
	IP           string
	FirstSeen    time.Time
	LastSeen     time.Time
	TotalScore   int
	ThreatCounts map[ThreatType]int
	Lines        []string
}

// DefaultDetectorConfig 默认检测器配置
func DefaultDetectorConfig() *DetectorConfig {
	return &DetectorConfig{
		BlockThreshold:            100,
		TimeWindowSeconds:         300, // 5 分钟
		EnableBruteForceDetection: true,
		EnableScanningDetection:   true,
		EnableInjectionDetection:  true,
		EnableBotDetection:        true,
	}
}

// NewThreatDetector 创建威胁检测器
func NewThreatDetector(config *DetectorConfig) *ThreatDetector {
	if config == nil {
		config = DefaultDetectorConfig()
	}

	td := &ThreatDetector{
		config:     config,
		ipTracker:  make(map[string]*IPActivity),
		threatChan: make(chan *Threat, 100),
	}

	td.initPatterns()
	go td.cleanupLoop()

	return td
}

// initPatterns 初始化检测模式
func (d *ThreatDetector) initPatterns() {
	d.patterns = []DetectionPattern{
		// SSH 暴力破解
		{
			Name:        "SSH Failed Password",
			Type:        ThreatTypeBruteForce,
			Pattern:     regexp.MustCompile(`Failed password for .* from (\d+\.\d+\.\d+\.\d+)`),
			Score:       20,
			Description: "SSH 登录失败",
			IPExtractor: extractIPFromMatch,
		},
		{
			Name:        "SSH Invalid User",
			Type:        ThreatTypeBruteForce,
			Pattern:     regexp.MustCompile(`Invalid user .* from (\d+\.\d+\.\d+\.\d+)`),
			Score:       25,
			Description: "SSH 无效用户尝试",
			IPExtractor: extractIPFromMatch,
		},
		{
			Name:        "SSH Too Many Auth Failures",
			Type:        ThreatTypeBruteForce,
			Pattern:     regexp.MustCompile(`Disconnecting.*: Too many authentication failures.*from (\d+\.\d+\.\d+\.\d+)`),
			Score:       50,
			Description: "SSH 认证失败次数过多",
			IPExtractor: extractIPFromMatch,
		},

		// Web 扫描
		{
			Name:        "Nginx 404 Scanner",
			Type:        ThreatTypeScanning,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST|HEAD).*(\.php|\.asp|\.aspx|\.jsp|wp-admin|wp-login|phpmyadmin|admin|\.env|\.git|\.svn).*" 404`),
			Score:       15,
			Description: "扫描敏感路径",
			IPExtractor: extractIPFromMatch,
		},
		{
			Name:        "Nginx 403 Scanner",
			Type:        ThreatTypeScanning,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST).*(\.php|\.asp|admin|config).*" 403`),
			Score:       10,
			Description: "访问禁止路径",
			IPExtractor: extractIPFromMatch,
		},

		// SQL 注入
		{
			Name:        "SQL Injection Attempt",
			Type:        ThreatTypeSQLInjection,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST).*(\bunion\b.*\bselect\b|\bor\b.*=.*\bor\b|'.*--|\bexec\b|\bdrop\b.*\btable\b|1=1|1'='1)`),
			Score:       40,
			Description: "SQL 注入尝试",
			IPExtractor: extractIPFromMatch,
		},

		// XSS 攻击
		{
			Name:        "XSS Attempt",
			Type:        ThreatTypeXSS,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST).*(<script|javascript:|onerror=|onload=|onclick=|%3Cscript)`),
			Score:       35,
			Description: "XSS 攻击尝试",
			IPExtractor: extractIPFromMatch,
		},

		// 路径遍历
		{
			Name:        "Path Traversal",
			Type:        ThreatTypePathTraversal,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST).*(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e)`),
			Score:       30,
			Description: "路径遍历攻击",
			IPExtractor: extractIPFromMatch,
		},

		// 恶意爬虫
		{
			Name:        "Malicious Bot",
			Type:        ThreatTypeBotAbuse,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST).*".*(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|hydra)`),
			Score:       50,
			Description: "恶意扫描工具",
			IPExtractor: extractIPFromMatch,
		},

		// 高频请求（潜在 DDoS）
		{
			Name:        "High Frequency Request",
			Type:        ThreatTypeDDoS,
			Pattern:     regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+).*"(GET|POST|HEAD).*" [2345]\d\d`),
			Score:       1, // 低分，需要累积
			Description: "高频请求",
			IPExtractor: extractIPFromMatch,
		},
	}
}

// extractIPFromMatch 从正则匹配中提取 IP
func extractIPFromMatch(line string) string {
	ipPattern := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)`)
	matches := ipPattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// Analyze 分析日志行
func (d *ThreatDetector) Analyze(line, source string) *Threat {
	d.mu.Lock()
	defer d.mu.Unlock()

	var detectedThreat *Threat

	for _, pattern := range d.patterns {
		// 检查是否启用该类型检测
		if !d.isDetectionEnabled(pattern.Type) {
			continue
		}

		if pattern.Pattern.MatchString(line) {
			ip := pattern.IPExtractor(line)
			if ip == "" {
				continue
			}

			// 跳过私有 IP
			if isPrivateIP(ip) {
				continue
			}

			// 更新 IP 活动记录
			activity := d.getOrCreateActivity(ip)
			activity.LastSeen = time.Now()
			activity.TotalScore += pattern.Score
			activity.ThreatCounts[pattern.Type]++
			activity.Lines = append(activity.Lines, line)

			// 限制保存的日志行数
			if len(activity.Lines) > 100 {
				activity.Lines = activity.Lines[len(activity.Lines)-100:]
			}

			// 创建威胁记录
			threat := &Threat{
				ID:          generateThreatID(),
				IP:          ip,
				Type:        pattern.Type,
				Score:       activity.TotalScore,
				Description: pattern.Description,
				Source:      source,
				Line:        line,
				Timestamp:   time.Now(),
				Count:       activity.ThreatCounts[pattern.Type],
			}

			// 如果分数超过阈值，发送到通道
			if activity.TotalScore >= d.config.BlockThreshold {
				select {
				case d.threatChan <- threat:
				default:
				}
			}

			// 返回最高分的威胁
			if detectedThreat == nil || threat.Score > detectedThreat.Score {
				detectedThreat = threat
			}
		}
	}

	return detectedThreat
}

// isDetectionEnabled 检查检测类型是否启用
func (d *ThreatDetector) isDetectionEnabled(threatType ThreatType) bool {
	switch threatType {
	case ThreatTypeBruteForce:
		return d.config.EnableBruteForceDetection
	case ThreatTypeScanning:
		return d.config.EnableScanningDetection
	case ThreatTypeSQLInjection, ThreatTypeXSS, ThreatTypePathTraversal:
		return d.config.EnableInjectionDetection
	case ThreatTypeBotAbuse:
		return d.config.EnableBotDetection
	default:
		return true
	}
}

// getOrCreateActivity 获取或创建 IP 活动记录
func (d *ThreatDetector) getOrCreateActivity(ip string) *IPActivity {
	activity, exists := d.ipTracker[ip]
	if !exists {
		activity = &IPActivity{
			IP:           ip,
			FirstSeen:    time.Now(),
			LastSeen:     time.Now(),
			TotalScore:   0,
			ThreatCounts: make(map[ThreatType]int),
			Lines:        make([]string, 0),
		}
		d.ipTracker[ip] = activity
	}
	return activity
}

// cleanupLoop 清理过期的 IP 活动记录
func (d *ThreatDetector) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.cleanup()
	}
}

// cleanup 清理过期记录
func (d *ThreatDetector) cleanup() {
	d.mu.Lock()
	defer d.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(d.config.TimeWindowSeconds) * time.Second)

	for ip, activity := range d.ipTracker {
		if activity.LastSeen.Before(cutoff) {
			delete(d.ipTracker, ip)
		}
	}
}

// GetIPActivity 获取 IP 活动记录
func (d *ThreatDetector) GetIPActivity(ip string) *IPActivity {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if activity, exists := d.ipTracker[ip]; exists {
		// 返回副本
		return &IPActivity{
			IP:           activity.IP,
			FirstSeen:    activity.FirstSeen,
			LastSeen:     activity.LastSeen,
			TotalScore:   activity.TotalScore,
			ThreatCounts: activity.ThreatCounts,
			Lines:        activity.Lines,
		}
	}
	return nil
}

// GetAllActivities 获取所有 IP 活动记录
func (d *ThreatDetector) GetAllActivities() []*IPActivity {
	d.mu.RLock()
	defer d.mu.RUnlock()

	activities := make([]*IPActivity, 0, len(d.ipTracker))
	for _, activity := range d.ipTracker {
		activities = append(activities, &IPActivity{
			IP:           activity.IP,
			FirstSeen:    activity.FirstSeen,
			LastSeen:     activity.LastSeen,
			TotalScore:   activity.TotalScore,
			ThreatCounts: activity.ThreatCounts,
		})
	}
	return activities
}

// GetHighRiskIPs 获取高风险 IP 列表
func (d *ThreatDetector) GetHighRiskIPs(minScore int) []*IPActivity {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var highRisk []*IPActivity
	for _, activity := range d.ipTracker {
		if activity.TotalScore >= minScore {
			highRisk = append(highRisk, &IPActivity{
				IP:           activity.IP,
				FirstSeen:    activity.FirstSeen,
				LastSeen:     activity.LastSeen,
				TotalScore:   activity.TotalScore,
				ThreatCounts: activity.ThreatCounts,
			})
		}
	}
	return highRisk
}

// Threats 返回威胁通道
func (d *ThreatDetector) Threats() <-chan *Threat {
	return d.threatChan
}

// ResetIP 重置 IP 的活动记录
func (d *ThreatDetector) ResetIP(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.ipTracker, ip)
}

// isPrivateIP 检查是否为私有 IP
func isPrivateIP(ip string) bool {
	privateRanges := []string{
		"10.",
		"172.16.", "172.17.", "172.18.", "172.19.",
		"172.20.", "172.21.", "172.22.", "172.23.",
		"172.24.", "172.25.", "172.26.", "172.27.",
		"172.28.", "172.29.", "172.30.", "172.31.",
		"192.168.",
		"127.",
		"0.",
	}

	for _, prefix := range privateRanges {
		if strings.HasPrefix(ip, prefix) {
			return true
		}
	}
	return false
}

// generateThreatID 生成威胁 ID
func generateThreatID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(8)
}

// randomString 生成随机字符串
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[time.Now().UnixNano()%int64(len(letters))]
		time.Sleep(1 * time.Nanosecond)
	}
	return string(b)
}
