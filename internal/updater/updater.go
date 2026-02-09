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
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	releaseURL     = "https://api.github.com/repos/Zhang142857/runixo-agent/releases/latest"
	apiTimeout     = 15 * time.Second
	downloadTimeout = 10 * time.Minute
	applyCooldown  = 60 * time.Second // 防止 DoS 反复触发更新
)

var versionRegex = regexp.MustCompile(`^v\d+\.\d+\.\d+(-[\w.]+)?$`)

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
		CheckInterval: 3600,
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
	Status     string `json:"status"`
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
	lastApply      time.Time // 防 DoS 冷却
}

// NewUpdater 创建更新器
func NewUpdater(currentVersion, dataDir string) (*Updater, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
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

	u.loadConfig()
	u.loadHistory()

	return u, nil
}

// loadConfig 加载配置
func (u *Updater) loadConfig() {
	configFile := filepath.Join(u.dataDir, "update_config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
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
	return os.WriteFile(configFile, data, 0600)
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
	return os.WriteFile(historyFile, data, 0600)
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

	log.Info().Int("interval", u.config.CheckInterval).Msg("自动更新已启动")
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
		return
	}

	log.Info().Str("current", info.CurrentVersion).Str("latest", info.LatestVersion).Msg("发现新版本")

	if u.config.NotifyOnly && !info.IsCritical {
		return
	}

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

	httpClient := &http.Client{Timeout: apiTimeout}
	resp, err := httpClient.Get(releaseURL)
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
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&release); err != nil {
		return nil, fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}

	// 验证版本号格式
	if !versionRegex.MatchString(release.TagName) {
		return nil, fmt.Errorf("无效的版本号格式: %s", release.TagName)
	}

	// 查找当前平台的二进制（tar.gz）
	assetSuffix := fmt.Sprintf("%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	var downloadURL string
	var size int64
	var checksum string
	for _, a := range release.Assets {
		if a.Name == "runixo-agent-"+assetSuffix {
			downloadURL = a.URL
			size = a.Size
		}
		if a.Name == "checksums.txt" {
			checksum = a.URL // 后续下载校验文件
		}
	}

	available := downloadURL != "" && release.TagName != u.currentVersion

	return &UpdateInfo{
		Available:      available,
		CurrentVersion: u.currentVersion,
		LatestVersion:  release.TagName,
		ReleaseNotes:   release.Body,
		DownloadURL:    downloadURL,
		Size:           size,
		Checksum:       checksum,
		ReleaseDate:    release.PublishedAt,
	}, nil
}

// DownloadUpdate 下载更新
func (u *Updater) DownloadUpdate(version string, progressChan chan<- *DownloadProgress) (string, error) {
	info, err := u.CheckUpdate()
	if err != nil {
		return "", err
	}
	if !info.Available || info.LatestVersion != version {
		return "", fmt.Errorf("版本 %s 不可用", version)
	}
	return u.downloadAndExtract(info, progressChan)
}

// downloadFile 下载文件（带总超时）
func (u *Updater) downloadFile(downloadURL, destPath string, totalSize int64, progressChan chan<- *DownloadProgress) error {
	ctx, cancel := context.WithTimeout(u.ctx, downloadTimeout)
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

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("下载失败: %s", resp.Status)
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer out.Close()

	var downloaded int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if _, writeErr := out.Write(buf[:n]); writeErr != nil {
				return writeErr
			}
			downloaded += int64(n)
			if progressChan != nil && totalSize > 0 {
				progressChan <- &DownloadProgress{
					Downloaded: downloaded, Total: totalSize,
					Percent: int(float64(downloaded) / float64(totalSize) * 100),
					Status: "downloading",
				}
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	return nil
}

// ApplyUpdate 应用更新
func (u *Updater) ApplyUpdate(version string) error {
	// 冷却检查，防止 DoS
	u.mu.Lock()
	if time.Since(u.lastApply) < applyCooldown {
		u.mu.Unlock()
		return fmt.Errorf("更新冷却中，请 %d 秒后重试", int(applyCooldown.Seconds()))
	}
	u.lastApply = time.Now()
	u.mu.Unlock()

	if !versionRegex.MatchString(version) {
		return fmt.Errorf("无效的版本号: %s", version)
	}

	info, err := u.CheckUpdate()
	if err != nil {
		return fmt.Errorf("获取更新信息失败: %w", err)
	}
	if !info.Available {
		return fmt.Errorf("没有可用更新")
	}

	downloadDir := filepath.Join(u.dataDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0700); err != nil {
		return err
	}

	binaryPath := filepath.Join(downloadDir, "runixo-agent")
	if runtime.GOOS == "windows" {
		binaryPath += ".exe"
	}

	if err := u.downloadFile(info.DownloadURL, binaryPath, info.Size, nil); err != nil {
		return fmt.Errorf("下载失败: %w", err)
	}

	return u.applyBinary(binaryPath, version)
}

// downloadAndExtract 下载 tar.gz 并提取二进制
func (u *Updater) downloadAndExtract(info *UpdateInfo, progressChan chan<- *DownloadProgress) (string, error) {
	downloadDir := filepath.Join(u.dataDir, "downloads")
	if err := os.MkdirAll(downloadDir, 0700); err != nil {
		return "", err
	}

	tarPath := filepath.Join(downloadDir, fmt.Sprintf("runixo-agent-%s.tar.gz", info.LatestVersion))
	if err := u.downloadFile(info.DownloadURL, tarPath, info.Size, progressChan); err != nil {
		return "", err
	}

	if progressChan != nil {
		progressChan <- &DownloadProgress{Downloaded: info.Size, Total: info.Size, Percent: 100, Status: "verifying"}
	}

	// 强制校验和验证：下载 checksums.txt 并比对
	if info.Checksum != "" {
		checksumValue, err := fetchChecksumForFile(info.Checksum, fmt.Sprintf("runixo-agent-%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH))
		if err != nil {
			os.Remove(tarPath)
			return "", fmt.Errorf("获取校验和失败: %w", err)
		}
		valid, err := verifyChecksum(tarPath, checksumValue)
		if err != nil {
			os.Remove(tarPath)
			return "", fmt.Errorf("验证校验和失败: %w", err)
		}
		if !valid {
			os.Remove(tarPath)
			return "", fmt.Errorf("校验和不匹配，文件可能被篡改")
		}
	} else {
		os.Remove(tarPath)
		return "", fmt.Errorf("缺少校验和信息，拒绝安装未验证的更新")
	}

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

// applyBinary 替换当前二进制并重启（原子 rename）
func (u *Updater) applyBinary(binaryPath, version string) error {
	if _, err := os.Stat(binaryPath); os.IsNotExist(err) {
		return fmt.Errorf("更新文件不存在: %s", binaryPath)
	}

	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("获取当前可执行文件路径失败: %w", err)
	}
	// 解析符号链接，防止符号链接攻击
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("解析符号链接失败: %w", err)
	}

	backupPath := currentExe + ".backup"

	// 备份当前版本
	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("备份当前版本失败: %w", err)
	}

	// 原子替换：rename 比 copy 更安全（同文件系统下原子操作）
	if err := os.Rename(binaryPath, currentExe); err != nil {
		// rename 失败（跨文件系统），回退到 copy
		if cpErr := copyFile(binaryPath, currentExe); cpErr != nil {
			os.Rename(backupPath, currentExe) // 回滚
			return fmt.Errorf("安装新版本失败: %w", cpErr)
		}
		os.Remove(binaryPath)
	}

	if runtime.GOOS != "windows" {
		os.Chmod(currentExe, 0755)
	}

	u.recordUpdate(version, true, "")
	log.Info().Str("version", version).Msg("更新已应用，即将重启服务")
	go u.restartService()
	return nil
}

// DownloadAndApply 下载并应用更新
func (u *Updater) DownloadAndApply(info *UpdateInfo) error {
	progressChan := make(chan *DownloadProgress, 10)
	defer close(progressChan)

	go func() {
		for p := range progressChan {
			log.Debug().Int("percent", p.Percent).Str("status", p.Status).Msg("下载进度")
		}
	}()

	binaryPath, err := u.downloadAndExtract(info, progressChan)
	if err != nil {
		return err
	}
	return u.applyBinary(binaryPath, info.LatestVersion)
}

// restartService 重启服务
func (u *Updater) restartService() {
	time.Sleep(2 * time.Second)
	if runtime.GOOS == "linux" {
		if exec.Command("systemctl", "restart", "runixo-agent").Run() == nil {
			return
		}
	}
	log.Info().Msg("正在重启...")
	os.Exit(0)
}

// recordUpdate 记录更新
func (u *Updater) recordUpdate(version string, success bool, errMsg string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.history = append(u.history, UpdateRecord{
		Version: version, FromVersion: u.currentVersion,
		Timestamp: time.Now().Unix(), Success: success, Error: errMsg,
	})
	if len(u.history) > 50 {
		u.history = u.history[len(u.history)-50:]
	}
	u.saveHistory()
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
	if u.checkTicker != nil {
		u.checkTicker.Stop()
	}
	if config.AutoUpdate {
		u.checkTicker = time.NewTicker(time.Duration(config.CheckInterval) * time.Second)
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

// fetchChecksumForFile 从 checksums.txt URL 下载并解析指定文件的 SHA256 值
func fetchChecksumForFile(checksumURL, filename string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), apiTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("下载校验和文件失败: %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB limit
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(body), "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == filename {
			return parts[0], nil
		}
	}
	return "", fmt.Errorf("checksums.txt 中未找到 %s 的校验和", filename)
}

// verifyChecksum 验证 SHA256 校验和
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
	return hex.EncodeToString(h.Sum(nil)) == expected, nil
}

// copyFile 复制文件（跨文件系统 fallback）
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
