// Package cloudflare 日志监控器
package cloudflare

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog/log"
)

// LogWatcher 日志监控器
type LogWatcher struct {
	paths      []string
	detector   *ThreatDetector
	blocker    *IPBlocker
	watcher    *fsnotify.Watcher
	ctx        context.Context
	cancel     context.CancelFunc
	mu         sync.RWMutex
	running    bool
	eventChan  chan LogEvent
	fileStates map[string]*fileState
}

// fileState 文件状态
type fileState struct {
	offset int64
	inode  uint64
}

// LogEvent 日志事件
type LogEvent struct {
	Timestamp time.Time `json:"timestamp"`
	Source    string    `json:"source"`
	Line      string    `json:"line"`
	IP        string    `json:"ip,omitempty"`
	Type      string    `json:"type,omitempty"`
}

// WatcherConfig 监控器配置
type WatcherConfig struct {
	// 要监控的日志文件路径
	LogPaths []string `json:"log_paths"`
	// 是否启用自动封禁
	AutoBlock bool `json:"auto_block"`
	// 封禁阈值（触发次数）
	BlockThreshold int `json:"block_threshold"`
	// 检测时间窗口（秒）
	TimeWindowSeconds int `json:"time_window_seconds"`
	// 封禁时长（秒），0 表示永久
	BlockDurationSeconds int `json:"block_duration_seconds"`
}

// DefaultWatcherConfig 默认监控配置
func DefaultWatcherConfig() *WatcherConfig {
	return &WatcherConfig{
		LogPaths: []string{
			"/var/log/auth.log",
			"/var/log/secure",
			"/var/log/nginx/access.log",
			"/var/log/nginx/error.log",
			"/var/log/apache2/access.log",
			"/var/log/apache2/error.log",
		},
		AutoBlock:            true,
		BlockThreshold:       5,
		TimeWindowSeconds:    300, // 5 分钟
		BlockDurationSeconds: 3600, // 1 小时
	}
}

// NewLogWatcher 创建日志监控器
func NewLogWatcher(config *WatcherConfig, detector *ThreatDetector, blocker *IPBlocker) (*LogWatcher, error) {
	if config == nil {
		config = DefaultWatcherConfig()
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	lw := &LogWatcher{
		paths:      config.LogPaths,
		detector:   detector,
		blocker:    blocker,
		watcher:    watcher,
		ctx:        ctx,
		cancel:     cancel,
		eventChan:  make(chan LogEvent, 1000),
		fileStates: make(map[string]*fileState),
	}

	return lw, nil
}

// Start 启动监控
func (w *LogWatcher) Start() error {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return nil
	}
	w.running = true
	w.mu.Unlock()

	// 添加要监控的文件
	for _, path := range w.paths {
		// 检查文件是否存在
		if _, err := os.Stat(path); os.IsNotExist(err) {
			log.Debug().Str("path", path).Msg("日志文件不存在，跳过")
			continue
		}

		// 监控文件所在目录（以便检测文件轮转）
		dir := filepath.Dir(path)
		if err := w.watcher.Add(dir); err != nil {
			log.Warn().Err(err).Str("dir", dir).Msg("添加目录监控失败")
		}

		// 初始化文件状态
		w.initFileState(path)
	}

	// 启动事件处理协程
	go w.watchLoop()
	go w.processEvents()

	log.Info().Strs("paths", w.paths).Msg("日志监控已启动")
	return nil
}

// Stop 停止监控
func (w *LogWatcher) Stop() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.running {
		return
	}

	w.cancel()
	w.watcher.Close()
	close(w.eventChan)
	w.running = false

	log.Info().Msg("日志监控已停止")
}

// initFileState 初始化文件状态
func (w *LogWatcher) initFileState(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}

	w.fileStates[path] = &fileState{
		offset: info.Size(), // 从文件末尾开始
	}
}

// watchLoop 监控循环
func (w *LogWatcher) watchLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return

		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			// 检查是否是我们监控的文件
			for _, path := range w.paths {
				if event.Name == path {
					if event.Op&fsnotify.Write == fsnotify.Write {
						w.readNewLines(path)
					}
				}
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			log.Error().Err(err).Msg("文件监控错误")

		case <-ticker.C:
			// 定期检查文件变化（处理某些系统不触发事件的情况）
			for _, path := range w.paths {
				w.readNewLines(path)
			}
		}
	}
}

// readNewLines 读取新行
func (w *LogWatcher) readNewLines(path string) {
	state, exists := w.fileStates[path]
	if !exists {
		w.initFileState(path)
		state = w.fileStates[path]
		if state == nil {
			return
		}
	}

	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	// 获取当前文件大小
	info, err := file.Stat()
	if err != nil {
		return
	}

	// 检查文件是否被轮转（大小变小）
	if info.Size() < state.offset {
		state.offset = 0
	}

	// 如果没有新内容，返回
	if info.Size() == state.offset {
		return
	}

	// 定位到上次读取位置
	if _, err := file.Seek(state.offset, 0); err != nil {
		return
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		event := LogEvent{
			Timestamp: time.Now(),
			Source:    path,
			Line:      line,
		}

		select {
		case w.eventChan <- event:
		default:
			// 通道满了，丢弃旧事件
			log.Warn().Msg("日志事件通道已满，丢弃事件")
		}
	}

	// 更新偏移量
	state.offset = info.Size()
}

// processEvents 处理日志事件
func (w *LogWatcher) processEvents() {
	for {
		select {
		case <-w.ctx.Done():
			return

		case event, ok := <-w.eventChan:
			if !ok {
				return
			}

			// 使用威胁检测器分析日志行
			if w.detector != nil {
				threat := w.detector.Analyze(event.Line, event.Source)
				if threat != nil {
					log.Warn().
						Str("ip", threat.IP).
						Str("type", string(threat.Type)).
						Int("score", threat.Score).
						Str("source", event.Source).
						Msg("检测到威胁")

					// 如果启用了自动封禁且分数超过阈值
					if w.blocker != nil && threat.Score >= w.detector.config.BlockThreshold {
						go w.blocker.BlockThreat(threat)
					}
				}
			}
		}
	}
}

// Events 返回事件通道（用于外部订阅）
func (w *LogWatcher) Events() <-chan LogEvent {
	return w.eventChan
}

// IsRunning 检查是否正在运行
func (w *LogWatcher) IsRunning() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.running
}

// AddPath 添加监控路径
func (w *LogWatcher) AddPath(path string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	// 检查是否已存在
	for _, p := range w.paths {
		if p == path {
			return nil
		}
	}

	w.paths = append(w.paths, path)

	if w.running {
		dir := filepath.Dir(path)
		if err := w.watcher.Add(dir); err != nil {
			return err
		}
		w.initFileState(path)
	}

	return nil
}

// RemovePath 移除监控路径
func (w *LogWatcher) RemovePath(path string) {
	w.mu.Lock()
	defer w.mu.Unlock()

	for i, p := range w.paths {
		if p == path {
			w.paths = append(w.paths[:i], w.paths[i+1:]...)
			delete(w.fileStates, path)
			break
		}
	}
}

// GetPaths 获取监控路径列表
func (w *LogWatcher) GetPaths() []string {
	w.mu.RLock()
	defer w.mu.RUnlock()

	paths := make([]string, len(w.paths))
	copy(paths, w.paths)
	return paths
}
