// Package plugin Agent 端插件管理系统
package plugin

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PluginState 插件状态
type PluginState string

const (
	StateInstalled PluginState = "installed"
	StateEnabled   PluginState = "enabled"
	StateDisabled  PluginState = "disabled"
	StateError     PluginState = "error"
	StateUpdating  PluginState = "updating"
)

// PluginType 插件类型
type PluginType string

const (
	TypeClient PluginType = "client" // 仅客户端
	TypeAgent  PluginType = "agent"  // 仅 Agent
	TypeHybrid PluginType = "hybrid" // 混合
)

// PluginManifest 插件清单
type PluginManifest struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Version      string         `json:"version"`
	Description  string         `json:"description"`
	Author       string         `json:"author"`
	Icon         string         `json:"icon"`
	Type         PluginType     `json:"type"`
	Permissions  []string       `json:"permissions"`
	EntryPoint   string         `json:"entry_point"` // 入口脚本或二进制
	Config       map[string]any `json:"config"`      // 默认配置
	Dependencies []string       `json:"dependencies"`
}

// InstalledPlugin 已安装的插件
type InstalledPlugin struct {
	Manifest    *PluginManifest `json:"manifest"`
	State       PluginState     `json:"state"`
	InstalledAt time.Time       `json:"installed_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Config      map[string]any  `json:"config"`
	Error       string          `json:"error,omitempty"`
}

// PluginStatus 插件运行状态
type PluginStatus struct {
	PluginID string            `json:"plugin_id"`
	State    PluginState       `json:"state"`
	Running  bool              `json:"running"`
	Error    string            `json:"error,omitempty"`
	Uptime   int64             `json:"uptime"`
	Stats    map[string]string `json:"stats"`
}

// Manager 插件管理器
type Manager struct {
	pluginsDir string
	plugins    map[string]*InstalledPlugin
	runtimes   map[string]*PluginRuntime
	mu         sync.RWMutex
	ctx        context.Context
	cancel     context.CancelFunc
	repoURL    string
}

// PluginRuntime 插件运行时接口
type PluginRuntime struct {
	plugin    *InstalledPlugin
	running   bool
	startTime time.Time
	stopChan  chan struct{}
	instance  PluginInstance
}

// PluginInstance 插件实例接口
type PluginInstance interface {
	Start(ctx context.Context, config map[string]any) error
	Stop() error
	GetStatus() map[string]string
}

// NewManager 创建插件管理器
func NewManager(pluginsDir string) (*Manager, error) {
	if err := os.MkdirAll(pluginsDir, 0755); err != nil {
		return nil, fmt.Errorf("创建插件目录失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	m := &Manager{
		pluginsDir: pluginsDir,
		plugins:    make(map[string]*InstalledPlugin),
		runtimes:   make(map[string]*PluginRuntime),
		ctx:        ctx,
		cancel:     cancel,
		repoURL:    "https://plugins.runixo.dev",
	}

	// 加载已安装的插件
	if err := m.loadPlugins(); err != nil {
		log.Warn().Err(err).Msg("加载插件列表失败")
	}

	return m, nil
}

// loadPlugins 加载已安装的插件
func (m *Manager) loadPlugins() error {
	installedFile := filepath.Join(m.pluginsDir, "installed.json")

	data, err := os.ReadFile(installedFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var plugins []*InstalledPlugin
	if err := json.Unmarshal(data, &plugins); err != nil {
		return err
	}

	for _, p := range plugins {
		m.plugins[p.Manifest.ID] = p
	}

	log.Info().Int("count", len(m.plugins)).Msg("已加载插件")
	return nil
}

// savePlugins 保存插件列表
func (m *Manager) savePlugins() error {
	m.mu.RLock()
	plugins := make([]*InstalledPlugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	m.mu.RUnlock()

	data, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return err
	}

	installedFile := filepath.Join(m.pluginsDir, "installed.json")
	return os.WriteFile(installedFile, data, 0644)
}

// ListPlugins 列出所有插件
func (m *Manager) ListPlugins() []*InstalledPlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugins := make([]*InstalledPlugin, 0, len(m.plugins))
	for _, p := range m.plugins {
		plugins = append(plugins, p)
	}
	return plugins
}

// GetPlugin 获取插件
func (m *Manager) GetPlugin(id string) *InstalledPlugin {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.plugins[id]
}

// InstallPlugin 安装插件
func (m *Manager) InstallPlugin(id, source, url string, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 检查是否已安装
	if _, exists := m.plugins[id]; exists {
		return fmt.Errorf("插件 %s 已安装", id)
	}

	pluginDir := filepath.Join(m.pluginsDir, id)

	var err error
	switch source {
	case "official":
		err = m.downloadFromRepo(id, pluginDir)
	case "url":
		err = m.downloadFromURL(url, pluginDir)
	case "local":
		err = m.extractFromData(data, pluginDir)
	default:
		return fmt.Errorf("未知的安装来源: %s", source)
	}

	if err != nil {
		os.RemoveAll(pluginDir)
		return fmt.Errorf("安装插件失败: %w", err)
	}

	// 读取插件清单
	manifest, err := m.readManifest(pluginDir)
	if err != nil {
		os.RemoveAll(pluginDir)
		return fmt.Errorf("读取插件清单失败: %w", err)
	}

	// 创建插件记录
	plugin := &InstalledPlugin{
		Manifest:    manifest,
		State:       StateInstalled,
		InstalledAt: time.Now(),
		UpdatedAt:   time.Now(),
		Config:      manifest.Config,
	}

	m.plugins[id] = plugin

	if err := m.savePlugins(); err != nil {
		log.Warn().Err(err).Msg("保存插件列表失败")
	}

	log.Info().Str("id", id).Str("version", manifest.Version).Msg("插件安装成功")
	return nil
}

// UninstallPlugin 卸载插件
func (m *Manager) UninstallPlugin(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[id]
	if !exists {
		return fmt.Errorf("插件 %s 未安装", id)
	}

	// 停止运行中的插件
	if runtime, ok := m.runtimes[id]; ok && runtime.running {
		if err := m.stopPluginLocked(id); err != nil {
			log.Warn().Err(err).Str("id", id).Msg("停止插件失败")
		}
	}

	// 删除插件目录
	pluginDir := filepath.Join(m.pluginsDir, id)
	if err := os.RemoveAll(pluginDir); err != nil {
		return fmt.Errorf("删除插件目录失败: %w", err)
	}

	delete(m.plugins, id)
	delete(m.runtimes, id)

	if err := m.savePlugins(); err != nil {
		log.Warn().Err(err).Msg("保存插件列表失败")
	}

	log.Info().Str("id", id).Str("name", plugin.Manifest.Name).Msg("插件已卸载")
	return nil
}

// EnablePlugin 启用插件
func (m *Manager) EnablePlugin(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[id]
	if !exists {
		return fmt.Errorf("插件 %s 未安装", id)
	}

	if plugin.State == StateEnabled {
		return nil
	}

	// 启动插件
	if err := m.startPluginLocked(id); err != nil {
		plugin.State = StateError
		plugin.Error = err.Error()
		return err
	}

	plugin.State = StateEnabled
	plugin.Error = ""

	if err := m.savePlugins(); err != nil {
		log.Warn().Err(err).Msg("保存插件列表失败")
	}

	log.Info().Str("id", id).Msg("插件已启用")
	return nil
}

// DisablePlugin 禁用插件
func (m *Manager) DisablePlugin(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[id]
	if !exists {
		return fmt.Errorf("插件 %s 未安装", id)
	}

	if plugin.State == StateDisabled {
		return nil
	}

	// 停止插件
	if err := m.stopPluginLocked(id); err != nil {
		log.Warn().Err(err).Str("id", id).Msg("停止插件失败")
	}

	plugin.State = StateDisabled

	if err := m.savePlugins(); err != nil {
		log.Warn().Err(err).Msg("保存插件列表失败")
	}

	log.Info().Str("id", id).Msg("插件已禁用")
	return nil
}

// GetPluginConfig 获取插件配置
func (m *Manager) GetPluginConfig(id string) (map[string]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[id]
	if !exists {
		return nil, fmt.Errorf("插件 %s 未安装", id)
	}

	return plugin.Config, nil
}

// SetPluginConfig 设置插件配置
func (m *Manager) SetPluginConfig(id string, config map[string]any) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	plugin, exists := m.plugins[id]
	if !exists {
		return fmt.Errorf("插件 %s 未安装", id)
	}

	plugin.Config = config
	plugin.UpdatedAt = time.Now()

	// 保存配置到文件
	configFile := filepath.Join(m.pluginsDir, id, "config.json")
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(configFile, data, 0644); err != nil {
		return err
	}

	// 通知运行中的插件配置已更新
	if runtime, ok := m.runtimes[id]; ok && runtime.running && runtime.instance != nil {
		// 重启插件以应用新配置
		m.stopPluginLocked(id)
		m.startPluginLocked(id)
	}

	if err := m.savePlugins(); err != nil {
		log.Warn().Err(err).Msg("保存插件列表失败")
	}

	return nil
}

// GetPluginStatus 获取插件状态
func (m *Manager) GetPluginStatus(id string) (*PluginStatus, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	plugin, exists := m.plugins[id]
	if !exists {
		return nil, fmt.Errorf("插件 %s 未安装", id)
	}

	status := &PluginStatus{
		PluginID: id,
		State:    plugin.State,
		Error:    plugin.Error,
		Stats:    make(map[string]string),
	}

	if runtime, ok := m.runtimes[id]; ok {
		status.Running = runtime.running
		if runtime.running {
			status.Uptime = int64(time.Since(runtime.startTime).Seconds())
			if runtime.instance != nil {
				status.Stats = runtime.instance.GetStatus()
			}
		}
	}

	return status, nil
}

// startPluginLocked 启动插件（需要持有锁）
func (m *Manager) startPluginLocked(id string) error {
	plugin := m.plugins[id]
	if plugin == nil {
		return fmt.Errorf("插件不存在")
	}

	// 只有 Agent 类型或混合类型的插件需要在 Agent 端运行
	if plugin.Manifest.Type == TypeClient {
		return nil
	}

	runtime := &PluginRuntime{
		plugin:   plugin,
		stopChan: make(chan struct{}),
	}

	// 根据插件类型创建实例
	instance, err := m.createPluginInstance(plugin)
	if err != nil {
		return err
	}

	runtime.instance = instance

	// 启动插件
	if err := instance.Start(m.ctx, plugin.Config); err != nil {
		return err
	}

	runtime.running = true
	runtime.startTime = time.Now()
	m.runtimes[id] = runtime

	return nil
}

// stopPluginLocked 停止插件（需要持有锁）
func (m *Manager) stopPluginLocked(id string) error {
	runtime, exists := m.runtimes[id]
	if !exists || !runtime.running {
		return nil
	}

	if runtime.instance != nil {
		if err := runtime.instance.Stop(); err != nil {
			return err
		}
	}

	close(runtime.stopChan)
	runtime.running = false
	delete(m.runtimes, id)

	return nil
}

// createPluginInstance 创建插件实例
func (m *Manager) createPluginInstance(plugin *InstalledPlugin) (PluginInstance, error) {
	// 根据插件 ID 创建对应的实例
	switch plugin.Manifest.ID {
	case "cloudflare-security":
		return NewCloudflarePlugin(m.pluginsDir, plugin.Manifest.ID)
	default:
		return NewGenericPlugin(m.pluginsDir, plugin.Manifest.ID)
	}
}

// downloadFromRepo 从官方仓库下载
func (m *Manager) downloadFromRepo(id, destDir string) error {
	url := fmt.Sprintf("%s/plugins/%s/latest.tar.gz", m.repoURL, id)
	return m.downloadFromURL(url, destDir)
}

// downloadFromURL 从 URL 下载
func (m *Manager) downloadFromURL(url, destDir string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: %s", resp.Status)
	}

	return m.extractTarGz(resp.Body, destDir)
}

// extractFromData 从数据解压
func (m *Manager) extractFromData(data []byte, destDir string) error {
	// 创建临时文件
	tmpFile, err := os.CreateTemp("", "plugin-*.tar.gz")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if _, err := tmpFile.Write(data); err != nil {
		return err
	}
	tmpFile.Seek(0, 0)

	return m.extractTarGz(tmpFile, destDir)
}

// extractTarGz 解压 tar.gz
func (m *Manager) extractTarGz(r io.Reader, destDir string) error {
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	gzr, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		target := filepath.Join(destDir, header.Name)

		// 路径穿越检查：确保解压目标在 destDir 内
		absTarget, err := filepath.Abs(target)
		if err != nil {
			return fmt.Errorf("解析路径失败: %w", err)
		}
		absDest, _ := filepath.Abs(destDir)
		if !strings.HasPrefix(absTarget, absDest+string(os.PathSeparator)) && absTarget != absDest {
			return fmt.Errorf("检测到路径穿越攻击: %s", header.Name)
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		}
	}

	return nil
}

// readManifest 读取插件清单
func (m *Manager) readManifest(pluginDir string) (*PluginManifest, error) {
	manifestFile := filepath.Join(pluginDir, "plugin.json")
	data, err := os.ReadFile(manifestFile)
	if err != nil {
		return nil, err
	}

	var manifest PluginManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return &manifest, nil
}

// StartEnabledPlugins 启动所有已启用的插件
func (m *Manager) StartEnabledPlugins() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id, plugin := range m.plugins {
		if plugin.State == StateEnabled {
			if err := m.startPluginLocked(id); err != nil {
				log.Error().Err(err).Str("id", id).Msg("启动插件失败")
				plugin.State = StateError
				plugin.Error = err.Error()
			}
		}
	}
}

// StopAllPlugins 停止所有插件
func (m *Manager) StopAllPlugins() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for id := range m.runtimes {
		if err := m.stopPluginLocked(id); err != nil {
			log.Warn().Err(err).Str("id", id).Msg("停止插件失败")
		}
	}
}

// Close 关闭管理器
func (m *Manager) Close() {
	m.cancel()
	m.StopAllPlugins()
}

// VerifyChecksum 验证文件校验和
func VerifyChecksum(filePath, expected string) (bool, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return false, err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return false, err
	}

	actual := hex.EncodeToString(h.Sum(nil))
	return actual == expected, nil
}
