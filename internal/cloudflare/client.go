// Package cloudflare 提供 Cloudflare API 客户端功能
package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	// CloudflareAPIBase Cloudflare API 基础 URL
	CloudflareAPIBase = "https://api.cloudflare.com/client/v4"
)

// Client Cloudflare API 客户端
type Client struct {
	apiToken   string
	accountID  string
	httpClient *http.Client
}

// Config Cloudflare 配置
type Config struct {
	APIToken  string `json:"api_token"`
	AccountID string `json:"account_id,omitempty"`
}

// Zone 域名信息
type Zone struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Status      string   `json:"status"`
	NameServers []string `json:"name_servers"`
	Plan        *Plan    `json:"plan,omitempty"`
}

// Plan 套餐信息
type Plan struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// DNSRecord DNS 记录
type DNSRecord struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	Proxied  bool   `json:"proxied"`
	TTL      int    `json:"ttl"`
	ZoneID   string `json:"zone_id"`
	ZoneName string `json:"zone_name"`
}

// FirewallRule 防火墙规则
type FirewallRule struct {
	ID          string  `json:"id"`
	Action      string  `json:"action"`
	Description string  `json:"description,omitempty"`
	Priority    int     `json:"priority,omitempty"`
	Filter      *Filter `json:"filter,omitempty"`
	Paused      bool    `json:"paused"`
}

// Filter 过滤器
type Filter struct {
	ID         string `json:"id"`
	Expression string `json:"expression"`
}

// AccessRule IP 访问规则
type AccessRule struct {
	ID            string              `json:"id"`
	Mode          string              `json:"mode"`
	Notes         string              `json:"notes,omitempty"`
	Configuration AccessRuleConfig    `json:"configuration"`
	CreatedOn     string              `json:"created_on,omitempty"`
	ModifiedOn    string              `json:"modified_on,omitempty"`
	Scope         *AccessRuleScope    `json:"scope,omitempty"`
}

// AccessRuleConfig 访问规则配置
type AccessRuleConfig struct {
	Target string `json:"target"`
	Value  string `json:"value"`
}

// AccessRuleScope 访问规则作用域
type AccessRuleScope struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// APIResponse Cloudflare API 响应
type APIResponse struct {
	Success  bool            `json:"success"`
	Errors   []APIError      `json:"errors"`
	Messages []string        `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

// APIError API 错误
type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// NewClient 创建新的 Cloudflare 客户端
func NewClient(config *Config) *Client {
	return &Client{
		apiToken:  config.APIToken,
		accountID: config.AccountID,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// request 发送 API 请求
func (c *Client) request(method, endpoint string, body interface{}) (*APIResponse, error) {
	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("序列化请求体失败: %w", err)
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequest(method, CloudflareAPIBase+endpoint, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %w", err)
	}
	defer resp.Body.Close()

	var apiResp APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("解析响应失败: %w", err)
	}

	if !apiResp.Success {
		if len(apiResp.Errors) > 0 {
			return nil, fmt.Errorf("API 错误: %s", apiResp.Errors[0].Message)
		}
		return nil, fmt.Errorf("API 请求失败")
	}

	return &apiResp, nil
}

// ListZones 列出所有域名
func (c *Client) ListZones() ([]Zone, error) {
	resp, err := c.request("GET", "/zones", nil)
	if err != nil {
		return nil, err
	}

	var zones []Zone
	if err := json.Unmarshal(resp.Result, &zones); err != nil {
		return nil, fmt.Errorf("解析域名列表失败: %w", err)
	}

	return zones, nil
}

// GetZone 获取域名信息
func (c *Client) GetZone(zoneID string) (*Zone, error) {
	resp, err := c.request("GET", "/zones/"+zoneID, nil)
	if err != nil {
		return nil, err
	}

	var zone Zone
	if err := json.Unmarshal(resp.Result, &zone); err != nil {
		return nil, fmt.Errorf("解析域名信息失败: %w", err)
	}

	return &zone, nil
}

// ListDNSRecords 列出 DNS 记录
func (c *Client) ListDNSRecords(zoneID string) ([]DNSRecord, error) {
	resp, err := c.request("GET", fmt.Sprintf("/zones/%s/dns_records", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var records []DNSRecord
	if err := json.Unmarshal(resp.Result, &records); err != nil {
		return nil, fmt.Errorf("解析 DNS 记录失败: %w", err)
	}

	return records, nil
}

// CreateDNSRecord 创建 DNS 记录
func (c *Client) CreateDNSRecord(zoneID string, record *DNSRecord) (*DNSRecord, error) {
	resp, err := c.request("POST", fmt.Sprintf("/zones/%s/dns_records", zoneID), record)
	if err != nil {
		return nil, err
	}

	var newRecord DNSRecord
	if err := json.Unmarshal(resp.Result, &newRecord); err != nil {
		return nil, fmt.Errorf("解析新 DNS 记录失败: %w", err)
	}

	return &newRecord, nil
}

// DeleteDNSRecord 删除 DNS 记录
func (c *Client) DeleteDNSRecord(zoneID, recordID string) error {
	_, err := c.request("DELETE", fmt.Sprintf("/zones/%s/dns_records/%s", zoneID, recordID), nil)
	return err
}

// PurgeCache 清除缓存
func (c *Client) PurgeCache(zoneID string, purgeEverything bool, files []string) error {
	body := make(map[string]interface{})
	if purgeEverything {
		body["purge_everything"] = true
	} else if len(files) > 0 {
		body["files"] = files
	} else {
		body["purge_everything"] = true
	}

	_, err := c.request("POST", fmt.Sprintf("/zones/%s/purge_cache", zoneID), body)
	return err
}

// GetSecurityLevel 获取安全级别
func (c *Client) GetSecurityLevel(zoneID string) (string, error) {
	resp, err := c.request("GET", fmt.Sprintf("/zones/%s/settings/security_level", zoneID), nil)
	if err != nil {
		return "", err
	}

	var result struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return "", fmt.Errorf("解析安全级别失败: %w", err)
	}

	return result.Value, nil
}

// SetSecurityLevel 设置安全级别
func (c *Client) SetSecurityLevel(zoneID, level string) error {
	body := map[string]string{"value": level}
	_, err := c.request("PATCH", fmt.Sprintf("/zones/%s/settings/security_level", zoneID), body)
	return err
}

// ListAccessRules 列出 IP 访问规则
func (c *Client) ListAccessRules(zoneID string) ([]AccessRule, error) {
	resp, err := c.request("GET", fmt.Sprintf("/zones/%s/firewall/access_rules/rules", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var rules []AccessRule
	if err := json.Unmarshal(resp.Result, &rules); err != nil {
		return nil, fmt.Errorf("解析访问规则失败: %w", err)
	}

	return rules, nil
}

// CreateAccessRule 创建 IP 访问规则（封禁/允许 IP）
func (c *Client) CreateAccessRule(zoneID string, mode string, ip string, notes string) (*AccessRule, error) {
	body := map[string]interface{}{
		"mode": mode,
		"configuration": map[string]string{
			"target": "ip",
			"value":  ip,
		},
		"notes": notes,
	}

	resp, err := c.request("POST", fmt.Sprintf("/zones/%s/firewall/access_rules/rules", zoneID), body)
	if err != nil {
		return nil, err
	}

	var rule AccessRule
	if err := json.Unmarshal(resp.Result, &rule); err != nil {
		return nil, fmt.Errorf("解析访问规则失败: %w", err)
	}

	return &rule, nil
}

// DeleteAccessRule 删除 IP 访问规则
func (c *Client) DeleteAccessRule(zoneID, ruleID string) error {
	_, err := c.request("DELETE", fmt.Sprintf("/zones/%s/firewall/access_rules/rules/%s", zoneID, ruleID), nil)
	return err
}

// BlockIP 封禁 IP
func (c *Client) BlockIP(zoneID, ip, reason string) (*AccessRule, error) {
	if reason == "" {
		reason = fmt.Sprintf("Blocked by Runixo at %s", time.Now().Format(time.RFC3339))
	}
	return c.CreateAccessRule(zoneID, "block", ip, reason)
}

// UnblockIP 解封 IP（通过删除规则）
func (c *Client) UnblockIP(zoneID, ruleID string) error {
	return c.DeleteAccessRule(zoneID, ruleID)
}

// ChallengeIP 对 IP 发起验证挑战
func (c *Client) ChallengeIP(zoneID, ip, reason string) (*AccessRule, error) {
	if reason == "" {
		reason = fmt.Sprintf("Challenged by Runixo at %s", time.Now().Format(time.RFC3339))
	}
	return c.CreateAccessRule(zoneID, "challenge", ip, reason)
}

// WhitelistIP 将 IP 加入白名单
func (c *Client) WhitelistIP(zoneID, ip, reason string) (*AccessRule, error) {
	if reason == "" {
		reason = fmt.Sprintf("Whitelisted by Runixo at %s", time.Now().Format(time.RFC3339))
	}
	return c.CreateAccessRule(zoneID, "whitelist", ip, reason)
}

// ListFirewallRules 列出防火墙规则
func (c *Client) ListFirewallRules(zoneID string) ([]FirewallRule, error) {
	resp, err := c.request("GET", fmt.Sprintf("/zones/%s/firewall/rules", zoneID), nil)
	if err != nil {
		return nil, err
	}

	var rules []FirewallRule
	if err := json.Unmarshal(resp.Result, &rules); err != nil {
		return nil, fmt.Errorf("解析防火墙规则失败: %w", err)
	}

	return rules, nil
}

// EnableUnderAttackMode 启用 Under Attack 模式
func (c *Client) EnableUnderAttackMode(zoneID string) error {
	return c.SetSecurityLevel(zoneID, "under_attack")
}

// DisableUnderAttackMode 禁用 Under Attack 模式（恢复为 medium）
func (c *Client) DisableUnderAttackMode(zoneID string) error {
	return c.SetSecurityLevel(zoneID, "medium")
}

// VerifyToken 验证 API Token 是否有效
func (c *Client) VerifyToken() (bool, error) {
	resp, err := c.request("GET", "/user/tokens/verify", nil)
	if err != nil {
		return false, err
	}

	var result struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return false, err
	}

	return result.Status == "active", nil
}
