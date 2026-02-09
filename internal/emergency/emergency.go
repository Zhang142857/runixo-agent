package emergency

import (
	"context"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/process"
)

// 阈值和时间窗口
const (
	DefaultCPUThreshold    = 95.0  // CPU 使用率阈值
	DefaultMemThreshold    = 95.0  // 内存使用率阈值
	MonitorInterval        = 20 * time.Second // 每 20 秒采样一次
	ConsecutiveDuration    = 3 * time.Minute  // 连续 3 分钟
	SamplesRequired        = int(ConsecutiveDuration / MonitorInterval) // 需要 9 个连续样本
	ProtectedPIDThreshold  = 2     // PID <= 2 不可杀
)

// KillRecord 记录一次紧急击杀
type KillRecord struct {
	PID       int32     `json:"pid"`
	Name      string    `json:"name"`
	Reason    string    `json:"reason"`
	CPU       float64   `json:"cpu"`
	Memory    float64   `json:"memory"`
	IsDocker  bool      `json:"is_docker"`
	Timestamp time.Time `json:"timestamp"`
}

// Config 紧急避险配置
type Config struct {
	CPUThreshold float64 `json:"cpu_threshold"`
	MemThreshold float64 `json:"mem_threshold"`
}

// Manager 紧急避险管理器
type Manager struct {
	mu              sync.RWMutex
	enabled         bool
	config          Config
	ctx             context.Context
	cancel          context.CancelFunc
	consecutiveHigh int // 连续超阈值的采样次数
	killHistory     []KillRecord
}

// New 创建管理器
func New() *Manager {
	return &Manager{
		config: Config{
			CPUThreshold: DefaultCPUThreshold,
			MemThreshold: DefaultMemThreshold,
		},
	}
}

// Enable 启用紧急避险
func (m *Manager) Enable() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.enabled {
		return
	}

	m.enabled = true
	m.consecutiveHigh = 0
	m.ctx, m.cancel = context.WithCancel(context.Background())

	go m.monitorLoop()
	log.Info().Msg("[紧急避险] 已启用")
}

// Disable 禁用紧急避险
func (m *Manager) Disable() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.enabled {
		return
	}

	m.enabled = false
	if m.cancel != nil {
		m.cancel()
	}
	m.consecutiveHigh = 0
	log.Info().Msg("[紧急避险] 已禁用")
}

// IsEnabled 是否启用
func (m *Manager) IsEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// GetStatus 获取状态
func (m *Manager) GetStatus() (enabled bool, consecutiveHigh int, history []KillRecord) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	// 返回最近 20 条记录
	h := m.killHistory
	if len(h) > 20 {
		h = h[len(h)-20:]
	}
	return m.enabled, m.consecutiveHigh, h
}

// SetConfig 更新配置
func (m *Manager) SetConfig(cfg Config) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cfg.CPUThreshold > 0 {
		m.config.CPUThreshold = cfg.CPUThreshold
	}
	if cfg.MemThreshold > 0 {
		m.config.MemThreshold = cfg.MemThreshold
	}
}

// monitorLoop 监控循环
func (m *Manager) monitorLoop() {
	ticker := time.NewTicker(MonitorInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.checkAndAct()
		}
	}
}

// checkAndAct 检查系统状态并在必要时采取行动
func (m *Manager) checkAndAct() {
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil || len(cpuPercent) == 0 {
		return
	}
	vmem, err := mem.VirtualMemory()
	if err != nil {
		return
	}

	cpuUsage := cpuPercent[0]
	memUsage := vmem.UsedPercent

	m.mu.Lock()
	cpuThresh := m.config.CPUThreshold
	memThresh := m.config.MemThreshold
	m.mu.Unlock()

	overloaded := cpuUsage >= cpuThresh || memUsage >= memThresh

	m.mu.Lock()
	if overloaded {
		m.consecutiveHigh++
		log.Warn().
			Float64("cpu", cpuUsage).
			Float64("mem", memUsage).
			Int("consecutive", m.consecutiveHigh).
			Int("required", SamplesRequired).
			Msg("[紧急避险] 系统负载过高")
	} else {
		m.consecutiveHigh = 0
	}
	shouldKill := m.consecutiveHigh >= SamplesRequired
	m.mu.Unlock()

	if shouldKill {
		m.killTopProcess(cpuUsage, memUsage)
		m.mu.Lock()
		m.consecutiveHigh = 0 // 重置计数器
		m.mu.Unlock()
	}
}

// processScore 计算进程的资源占用得分（越高越该被杀）
type processScore struct {
	pid         int32
	name        string
	cmdline     string
	cpuPercent  float64
	memPercent  float32
	score       float64
	containerID string // 非空表示是 Docker 容器
}

// killTopProcess 找到并杀掉占用最多资源的进程
func (m *Manager) killTopProcess(cpuUsage, memUsage float64) {
	procs, err := process.Processes()
	if err != nil {
		log.Error().Err(err).Msg("[紧急避险] 获取进程列表失败")
		return
	}

	var scored []processScore
	for _, p := range procs {
		if p.Pid <= ProtectedPIDThreshold {
			continue
		}

		name, _ := p.Name()
		// 跳过自身和关键系统进程
		if isProtectedProcess(name) {
			continue
		}

		cpuP, _ := p.CPUPercent()
		memP, _ := p.MemoryPercent()
		cmdline, _ := p.Cmdline()

		// 综合得分：CPU 权重 0.6 + 内存权重 0.4
		score := cpuP*0.6 + float64(memP)*0.4

		ps := processScore{
			pid: p.Pid, name: name, cmdline: cmdline,
			cpuPercent: cpuP, memPercent: memP, score: score,
		}

		// 检测是否为 Docker 容器进程
		ps.containerID = detectDockerContainer(p.Pid)

		scored = append(scored, ps)
	}

	if len(scored) == 0 {
		return
	}

	// 按得分降序排列
	sort.Slice(scored, func(i, j int) bool {
		return scored[i].score > scored[j].score
	})

	target := scored[0]
	if target.score < 1.0 {
		log.Info().Msg("[紧急避险] 没有找到高占用进程，跳过")
		return
	}

	record := KillRecord{
		PID:       target.pid,
		Name:      target.name,
		CPU:       target.cpuPercent,
		Memory:    float64(target.memPercent),
		IsDocker:  target.containerID != "",
		Timestamp: time.Now(),
	}

	if target.containerID != "" {
		record.Reason = fmt.Sprintf("Docker 容器 %s 资源占用过高", target.containerID)
		m.killDockerContainer(target.containerID)
	} else {
		record.Reason = fmt.Sprintf("进程 %s (PID %d) 资源占用过高 (CPU: %.1f%%, MEM: %.1f%%)",
			target.name, target.pid, target.cpuPercent, target.memPercent)
		m.killRegularProcess(target.pid, target.name)
	}

	log.Warn().
		Int32("pid", target.pid).
		Str("name", target.name).
		Str("container", target.containerID).
		Float64("cpu", target.cpuPercent).
		Float32("mem", target.memPercent).
		Msg("[紧急避险] 已执行强制终止")

	m.mu.Lock()
	m.killHistory = append(m.killHistory, record)
	m.mu.Unlock()
}

// killDockerContainer 停止 Docker 容器并禁用重启策略
func (m *Manager) killDockerContainer(containerID string) {
	// 先更新重启策略为 no，防止自动重启
	updateCmd := exec.Command("docker", "update", "--restart=no", containerID)
	if out, err := updateCmd.CombinedOutput(); err != nil {
		log.Error().Err(err).Str("output", string(out)).Msg("[紧急避险] 更新容器重启策略失败")
	}

	// 强制停止容器（给 5 秒优雅关闭时间）
	stopCmd := exec.Command("docker", "stop", "-t", "5", containerID)
	if out, err := stopCmd.CombinedOutput(); err != nil {
		log.Error().Err(err).Str("output", string(out)).Msg("[紧急避险] 停止容器失败，尝试 kill")
		killCmd := exec.Command("docker", "kill", containerID)
		killCmd.Run()
	}
}

// killRegularProcess 终止普通进程
func (m *Manager) killRegularProcess(pid int32, name string) {
	p, err := process.NewProcess(pid)
	if err != nil {
		return
	}

	// 先尝试 SIGTERM
	p.Terminate()

	// 等 3 秒，如果还活着就 SIGKILL
	time.Sleep(3 * time.Second)
	running, _ := p.IsRunning()
	if running {
		p.Kill()
	}

	// 如果是 systemd 管理的服务，禁用自动重启
	disableCmd := exec.Command("systemctl", "stop", name+".service")
	disableCmd.Run()
}

// detectDockerContainer 检测 PID 是否属于 Docker 容器
func detectDockerContainer(pid int32) string {
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	data, err := exec.Command("cat", cgroupPath).Output()
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		// Docker cgroup 路径包含容器 ID
		if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
			parts := strings.Split(line, "/")
			for _, part := range parts {
				// 容器 ID 是 64 位十六进制
				if len(part) == 64 && isHex(part) {
					return part[:12] // 返回短 ID
				}
			}
		}
	}
	return ""
}

// isHex 检查字符串是否为十六进制
func isHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isProtectedProcess 检查是否为受保护的系统进程
func isProtectedProcess(name string) bool {
	protected := map[string]bool{
		"init": true, "systemd": true, "sshd": true,
		"runixo-agent": true, "dockerd": true, "containerd": true,
		"kernel": true, "kthreadd": true, "ksoftirqd": true,
	}
	return protected[name]
}
