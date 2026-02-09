// Package updater Agent 自动更新系统
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Config 更新配置
type Config struct {
	AutoUpdate    bool   `json:"auto_update"`
	CheckInterval int    `json:"check_interval"` // 秒
	UpdateChannel string `json:"update_channel"` // stable, beta, nightly
	LastCheck     string `json:"last_check"`
	NotifyOnly    bool   `json:"notify_only"` // 仅通知，不自动安装
}

// DefaultConfig 默认配置
func DefaultConfig() *Config {
	return &Config{
		AutoUpdate:    false,
		CheckInterval: 3600, // 1小时
		UpdateChannel: "stable",
		NotifyOnly:    true,
	}
}

// UpdateInfo 更新信息
type UpdateInfo struct {
	Available      bool   `json:"available"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version"`
	ReleaseNotes   string `json:"release_notes"`
	DownloadURL    string `json:"download_url"`
	Size           int64  `json:"size"`
	Checksum       string `json:"checksum"`
	ReleaseDate    string `json:"release_date"`
	IsCritical     bool   `json:"is_critical"`
}

// UpdateRecord 更新记录
type UpdateRecord struct {
	Version     string `json:"version"`
	FromVersion string `json:"from_version"`
	Timestamp   int64  `json:"timestamp"`
	Success     bool   `json:"success"`
	Error       string `json:"error,omitempty"`
}

// DownloadProgress 下载进度
type DownloadProgress struct {
	Downloaded int64  `json:"downloaded"`
	Total      int64  `json:"total"`
	Percent    int    `json:"percent"`
	Status     string `json:"status"` // downloading, verifying, ready
}

// Updater 更新器
type Updater struct {
	config         *Config
	currentVersion string
	dataDir        string
	mu             sync.RWMutex
	ctx            context.Context
	cancel         context.CancelFunc
	checkTicker    *time.Ticker
	history        []UpdateRecord
	progressChan   chan *DownloadProgress
}

// NewUpdater 创建更新器
func NewUpdater(currentVersion, dataDir string) (*Updater, error) {
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("创建数据目录失败: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	u := &Updater{
		config:         DefaultConfig(),
		currentVersion: currentVersion,
		dataDir:        dataDir,
		ctx:            ctx,
		cancel:         cancel,
		progressChan:   make(chan *DownloadProgress, 10),
	}

	// 加载配置
	u.loadConfig()
	u.loadHistory()

	return u, nil
}

// loadConfig 加载配置
func (u *Updater) loadConfig() {
	configFile := filepath.Join(u.dataDir, "update_config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warn().Err(err).Msg("加载更新配置失败")
		}
		return
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		log.Warn().Err(err).Msg("解析更新配置失败")
		return
	}

	u.config = &config
}

// saveConfig 保存配置
func (u *Updater) saveConfig() error {
	configFile := filepath.Join(u.dataDir, "update_config.json")
	data, err := json.MarshalIndent(u.config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(configFile, data, 0644)
}

// loadHistory 加载更新历史
func (u *Updater) loadHistory() {
	historyFile := filepath.Join(u.dataDir, "update_history.json")
	data, err := os.ReadFile(historyFile)
	if err != nil {
		return
	}

	json.Unmarshal(data, &u.history)
}

// saveHistory 保存更新历史
func (u *Updater) saveHistory() error {
	historyFile := filepath.Join(u.dataDir, "update_history.json")
	data, err := json.MarshalIndent(u.history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(historyFile, data, 0644)
}

// Start 启动更新器
func (u *Updater) Start() {
	if !u.config.AutoUpdate {
		log.Info().Msg("自动更新已禁用")
		return
	}

	interval := time.Duration(u.config.CheckInterval) * time.Second
	u.checkTicker = time.NewTicker(interval)

	go func() {
		// 启动时检查一次
		u.checkAndUpdate()

		for {
			select {
			case <-u.ctx.Done():
				return
			case <-u.checkTicker.C:
				u.checkAndUpdate()
			}
		}
	}()

	log.Info().
		Int("interval", u.config.CheckInterval).
		Str("channel", u.config.UpdateChannel).
		Msg("自动更新已启动")
}

// Stop 停止更新器
func (u *Updater) Stop() {
	u.cancel()
	if u.checkTicker != nil {
		u.checkTicker.Stop()
	}
}

// checkAndUpdate 检查并更新
func (u *Updater) checkAndUpdate() {
	info, err := u.CheckUpdate()
	if err != nil {
		log.Warn().Err(err).Msg("检查更新失败")
		return
	}

	if !info.Available {
		log.Debug().Msg("当前已是最新版本")
		return
	}

	log.Info().
		Str("current", info.CurrentVersion).
		Str("latest", info.LatestVersion).
		Bool("critical", info.IsCritical).
		Msg("发现新版本")

	if u.config.NotifyOnly && !info.IsCritical {
		log.Info().Msg("仅通知模式，跳过自动更新")
		return
	}

	// 下载并应用更新
	if err := u.DownloadAndApply(info); err != nil {
		log.Error().Err(err).Msg("更新失败")
		u.recordUpdate(info.LatestVersion, false, err.Error())
	}
}

// CheckUpdate 检查更新（从 GitHub Releases 获取）
func (u *Updater) CheckUpdate() (*UpdateInfo, error) {
	u.mu.Lock()
	u.config.LastCheck = time.Now().Format(time.RFC3339)
	u.saveConfig()
	u.mu.Unlock()

	url := "https://api.github.com/repos/Zhang142857/runixo/releases/tags/latest"
	httpClient := &http.Client{Timeout: 15 * time.Second}
	resp, err := httpClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("请求 GitHub 失败: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub 返回错误: %s", resp.Status)
	}

	var release struct {
		TagName string `json:"tag_name"`
		Body    string `json:"body"`
		Assets  []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
			URL  string `json:"browser_download_url"`
		} `json:"assets"`
		PublishedAt string `json:"published_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}

	// 查找当前平台的二进制
	assetName := fmt.Sprintf("runixo-agent-%s-%s", runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	var size int64
	for _, a := range release.Assets {
		if a.Name == assetName {
			downloadURL = a.URL
			size = a.Size
			break
		}
	}

	// 比较版本：从 release 的 body 中提取 commit sha 或直接比较文件大小
	// 简单方案：如果 release 中有对应平台的文件，且当前版本不等于 latest tag，则有更新
	latestVersion := release.TagName
	available := downloadURL != "" && latestVersion != u.currentVersion

	return &UpdateInfo{
		Available:      available,
		CurrentVersion: u.currentVersion,
		LatestVersion:  latestVersion,
		ReleaseNotes:   release.Body,
		DownloadURL:    downloadURL,
		Size:           size,
		ReleaseDate:    release.PublishedAt,
	}, nil
}

// DownloadUpdate 下载更新
func (u *Updater) DownloadUpdate(version string, progressChan chan<- *DownloadProgress) (string, error) {
	// 获取更新信息
	info, err := u.CheckUpdate()
	if err != nil {
		return "", err
	}

	if !info.Available || info.LatestVersion != version {
		return "", fmt.Errorf("版本 %s 不可用", version)
	}

	return u.downloadAndExtract(info, progressChan)
}

// downloadFile 下载文件（使用 context 控制连接超时，不限制 body 读取时间）
func (u *Updater) downloadFile(downloadURL, destPath string, totalSize int64, progressChan chan<- *DownloadProgress) error {
	ctx, cancel := context.WithTimeout(u.ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 连接已建立，取消连接超时，后续读取不限时
	cancel()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: %s", resp.Status)
	}

	out, err := os.Create(destPath)
	if err != nil {
		return err
	}
	defer out.Close()

	// 带进度的复制
	var downloaded int64
	buf := make([]byte, 32*1024)

	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			downloaded += int64(n)

			if progressChan != nil && totalSize > 0 {
				percent := int(float64(downloaded) / float64(totalSize) * 100)
				progressChan <- &DownloadProgress{
					Downloaded: downloaded,
					Total:      totalSize,
					Percent:    percent,
					Status:     "downloading",
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	return nil
}

// ApplyUpdate 应用更新（先下载再替换二进制）
func (u *Updater) ApplyUpdate(version string) error {
	// 先检查更新获取下载信息
	info, err := u.CheckUpdate()
	if err != nil {
		return fmt.Errorf("获取更新信息失败: %w", err)
	}
	if !info.Available {
		return fmt.Errorf("没有可用更新")
	}

	// 下载二进制
	downloadDir := filepath.Join(u.dataDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return err
	}
	binaryPath := filepath.Join(downloadDir, "runixo-agent")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	log.Info().Str("url", info.DownloadURL).Msg("开始下载更新")
	if err := u.downloadFile(info.DownloadURL, binaryPath, info.Size, nil); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}

	return u.applyBinary(binaryPath, version)
}

// downloadAndExtract 下载 tar.gz 并提取二进制
func (u *Updater) downloadAndExtract(info *UpdateInfo, progressChan chan<- *DownloadProgress) (string, error) {
	downloadDir := filepath.Join(u.dataDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0755); err != nil {
		return "", err
	}

	// 下载 tar.gz
	tarPath := filepath.Join(downloadDir, fmt.Sprintf("runixo-agent-%s.tar.gz", info.LatestVersion))
	if err := u.downloadFile(info.DownloadURL, tarPath, info.Size, progressChan); err != nil {
		return "", err
	}

	// 验证校验和
	if progressChan != nil {
		progressChan <- &DownloadProgress{Downloaded: info.Size, Total: info.Size, Percent: 100, Status: "verifying"}
	}
	if info.Checksum != "" {
		valid, err := verifyChecksum(tarPath, info.Checksum)
		if err != nil {
			os.Remove(tarPath)
			return "", fmt.Errorf("验证校验和失败: %w", err)
		}
		if !valid {
			os.Remove(tarPath)
			return "", fmt.Errorf("校验和不匹配")
		}
	}

	// 解压提取二进制
	binaryName := "runixo-agent"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(downloadDir, binaryName)

	cmd := exec.Command("tar", "--no-same-owner", "-xzf", tarPath, "-C", downloadDir, binaryName)
	if output, err := cmd.CombinedOutput(); err != nil {
		os.Remove(tarPath)
		return "", fmt.Errorf("解压失败: %v, output: %s", err, string(output))
	}
	os.Remove(tarPath)

	if progressChan != nil {
		progressChan <- &DownloadProgress{Downloaded: info.Size, Total: info.Size, Percent: 100, Status: "ready"}
	}
	return binaryPath, nil
}

// applyBinary 替换当前二进制并重启
func (u *Updater) applyBinary(binaryPath, version string) error {
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return fmt.Errorf("更新文件不存在: %s", binaryPath)
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取当前可执行文件路径失败: %w", err)
	}

	// 备份 → 替换 → 设权限
	backupPath := currentExe + ".backup"
	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("备份当前版本失败: %w", err)
	}
	if err := copyFile(binaryPath, currentExe); err != nil {
		os.Rename(backupPath, currentExe)
		return fmt.Errorf("安装新版本失败: %w", err)
	}
	if runtime.GOOS != "windows" {
		os.Chmod(currentExe, 0755)
	}

	u.recordUpdate(version, true, "")
	os.Remove(binaryPath)
	log.Info().Str("version", version).Msg("更新已应用，即将重启服务")
	go u.restartService()
	return nil
}

// DownloadAndApply 下载并应用更新
func (u *Updater) DownloadAndApply(info *UpdateInfo) error {
	progressChan := make(chan *DownloadProgress, 10)
	defer close(progressChan)

	// 启动进度日志
	go func() {
		for p := range progressChan {
			log.Debug().
				Int64("downloaded", p.Downloaded).
				Int64("total", p.Total).
				Int("percent", p.Percent).
				Str("status", p.Status).
				Msg("下载进度")
		}
	}()

	// 直接下载，不再重复 CheckUpdate
	binaryPath, err := u.downloadAndExtract(info, progressChan)
	if err != nil {
		return err
	}

	// 应用（传入已解压的二进制路径）
	return u.applyBinary(binaryPath, info.LatestVersion)
}

// restartService 重启服务
func (u *Updater) restartService() {
	time.Sleep(2 * time.Second)

	// 尝试使用 systemctl 重启
	if runtime.GOOS == "linux" {
		cmd := exec.Command("systemctl", "restart", "runixo-agent")
		if err := cmd.Run(); err != nil {
			log.Warn().Err(err).Msg("systemctl 重启失败，尝试直接重启")
		} else {
			return
		}
	}

	// 直接退出，让进程管理器重启
	log.Info().Msg("正在重启...")
	os.Exit(0)
}

// recordUpdate 记录更新
func (u *Updater) recordUpdate(version string, success bool, errMsg string) {
	record := UpdateRecord{
		Version:     version,
		FromVersion: u.currentVersion,
		Timestamp:   time.Now().Unix(),
		Success:     success,
		Error:       errMsg,
	}

	u.mu.Lock()
	u.history = append(u.history, record)
	// 只保留最近 50 条记录
	if len(u.history) > 50 {
		u.history = u.history[len(u.history)-50:]
	}
	u.saveHistory()
	u.mu.Unlock()
}

// GetConfig 获取配置
func (u *Updater) GetConfig() *Config {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.config
}

// SetConfig 设置配置
func (u *Updater) SetConfig(config *Config) error {
	u.mu.Lock()
	defer u.mu.Unlock()

	u.config = config

	// 重新启动定时检查
	if u.checkTicker != nil {
		u.checkTicker.Stop()
	}

	if config.AutoUpdate {
		interval := time.Duration(config.CheckInterval) * time.Second
		u.checkTicker = time.NewTicker(interval)
	}

	return u.saveConfig()
}

// GetHistory 获取更新历史
func (u *Updater) GetHistory() []UpdateRecord {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return u.history
}

// GetCurrentVersion 获取当前版本
func (u *Updater) GetCurrentVersion() string {
	return u.currentVersion
}

// verifyChecksum 验证校验和
func verifyChecksum(filePath, expected string) (bool, error) {
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

// copyFile 复制文件
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}
